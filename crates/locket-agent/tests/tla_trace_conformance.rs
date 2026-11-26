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
        let live = locket_platform::current_process_binding().unwrap();
        Self { dir, path, state, binding: GrantBinding::new(live.pid, live.process_start_time) }
    }

    fn store(&self) -> Store {
        Store::open(&self.path).unwrap()
    }

    fn root(&self, project: Project) -> PathBuf {
        self.dir.path().join(project.label)
    }

    async fn rpc(&self, method: AgentMethod, payload: Value) -> ResponseEnvelope {
        let request = RequestEnvelope::new("tla-trace", method, payload);
        if method == AgentMethod::RequestGrant || request.payload["grant_id"].is_string() {
            locket_agent::dispatch_with_peer(&request, &self.state, Some(self.peer())).await
        } else {
            dispatch(&request, &self.state).await
        }
    }

    const fn peer(&self) -> locket_agent::PeerIdentity {
        locket_agent::PeerIdentity::new(self.state.daemon_uid, Some(self.binding.pid), 1)
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
    run.record("unlock", r#"<< {"ProjA"}, 1 >>"#).await;
    success(fixture.unlock(B, 120).await);
    run.record("unlock", r#"<< {"ProjB"}, 2 >>"#).await;

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
    run.record("unlock", r#"<< {"ProjA"}, 1 >>"#).await;
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

    // Exercise both key sources with the same batch and observe it as one step.
    let passphrase = "fixture-passphrase-for-project-b";
    fixture.state.master_key_store.store_master_key(A.id, &A.master()).unwrap();
    fixture
        .state
        .passphrase_store
        .store_master_key(B.id, &B.master(), passphrase.as_bytes(), now())
        .unwrap();
    let batch = fixture
        .rpc(
            AgentMethod::UnlockBatch,
            json!({
                "projects": [
                    {"project_id": A.id, "ttl_seconds": 120},
                    {"project_id": B.id, "ttl_seconds": 120, "passphrase": passphrase},
                ],
                "verify_user": false,
            }),
        )
        .await;
    assert_eq!(success(batch)["batch_size"], 2);
    run.record("unlock", r#"<< {"ProjA", "ProjB"}, 1 >>"#).await;
    let scoped_lock = fixture.rpc(AgentMethod::Lock, json!({"project_id": A.id})).await;
    success(scoped_lock);
    run.record("lock", r#"<< "ProjA" >>"#).await;
    assert!(fixture.state.unlock_cache.lock().await.lookup(B.id, i128::from(now())).is_some());
    let native_lock = fixture
        .state
        .lock_for_native_session_event(SessionLockSource::ScreenLock, true, i128::from(run.cutoff))
        .await
        .unwrap();
    assert_eq!(native_lock.cached_keys_cleared, 1);
    assert!(fixture.state.unlock_cache.lock().await.is_empty());
    run.record("nativeLock", "<<>>").await;

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

#[derive(Default)]
struct SharedLinksTrace {
    trace: Trace,
    target: String,
    reviewed: Option<SharedUsageReview>,
    published: bool,
}

struct SharedUsageReview {
    ids: Vec<String>,
    projection: String,
}

impl SharedLinksTrace {
    async fn record(
        &mut self,
        f: &Fixture,
        action: &str,
        input: impl Display + Send,
        read: Option<Project>,
    ) {
        let cache = f.state.unlock_cache.lock().await;
        let stamp = i128::from(now());
        let unlocked = [A, B, SHARED]
            .into_iter()
            .filter(|project| cache.lookup(project.id, stamp).is_some())
            .map(|project| format!("{:?}", project.label))
            .collect::<Vec<_>>()
            .join(", ");
        drop(cache);
        let store = f.store();
        let shared_exists = store
            .get_active_secret(SHARED.id, SHARED.profile, TOKEN, "user-local")
            .unwrap()
            .is_some();
        // Read the link rows directly, including any dangling row hidden by a usage join.
        let links = [A, B]
            .into_iter()
            .filter(|project| {
                store.get_secret_link(project.id, project.profile, TOKEN).unwrap().is_some()
            })
            .map(|project| format!("{:?}", project.label))
            .collect::<Vec<_>>()
            .join(", ");
        let dangerous = [A, B, SHARED]
            .into_iter()
            .filter(|project| {
                store.get_profile_by_name(project.id, "default").unwrap().unwrap().dangerous
            })
            .map(|project| format!("{:?}", project.label))
            .collect::<Vec<_>>()
            .join(", ");
        let [a_audits, b_audits] = [A, B].map(|project| self.unlink_count(f, project));
        let review =
            self.reviewed.as_ref().map_or(r#"{<<"none", 0>>}"#, |review| &review.projection);
        let read = read.map_or("none", |project| project.label);
        let publisher = if self.published { A.label } else { "none" };
        self.trace.record(
            action,
            input,
            &format!(
                "[unlocked |-> {{{unlocked}}}, sessionLocked |-> {}, sharedExists |-> {}, \
                 links |-> {{{links}}}, dangerous |-> {{{dangerous}}}, reviewedLinks |-> {review}, \
                 unlinkAudits |-> [ProjA |-> {a_audits}, ProjB |-> {b_audits}], linkedRead |-> {read:?}, \
                 teamExport |-> [project |-> {publisher:?}, links |-> {{}}, dedupTags |-> {{}}]]",
                tla_bool(f.session_blocked().await),
                tla_bool(shared_exists),
            ),
        );
    }

    fn unlink_count(&self, f: &Fixture, project: Project) -> usize {
        let mut count = 0;
        for (_, action, metadata) in f.audit_rows(project) {
            if action != "SECRET_UNLINK" {
                continue;
            }
            assert_eq!(metadata["status"], "SUCCESS");
            assert_eq!(metadata["secret_name"], TOKEN);
            assert_eq!(metadata["profile_id"], project.profile);
            assert_eq!(metadata["target_secret_id"], self.target);
            count += 1;
        }
        count
    }

    async fn unlock(&mut self, f: &Fixture, project: Project) {
        success(f.unlock(project, 120).await);
        self.record(f, "unlock", format!("<<{:?}>>", project.label), None).await;
    }

    async fn lock(&mut self, f: &Fixture, project: Project) {
        success(f.rpc(AgentMethod::Lock, json!({"project_id": project.id})).await);
        self.record(f, "lock", format!("<<{:?}>>", project.label), None).await;
    }

    async fn mutate_link(&mut self, f: &Fixture, project: Project, link: bool, confirmed: bool) {
        let (method, action, label) = if link {
            (AgentMethod::LinkSecret, GrantAction::LinkSecret, "link")
        } else {
            (AgentMethod::UnlinkSecret, GrantAction::UnlinkSecret, "unlink")
        };
        let grant = grant_id(f.grant(project, action, confirmed).await);
        let mut payload = f.scope(project, &grant);
        payload["local_name"] = json!(TOKEN);
        payload["target_secret_name"] = json!(TOKEN);
        payload["confirmation"] = json!(confirmed.then_some("default"));
        let result = success(f.rpc(method, payload).await);
        assert_eq!(result["local_name"], TOKEN);
        if link {
            assert_eq!(result["target_secret_id"], self.target);
            let persisted =
                f.store().get_secret_link(project.id, project.profile, TOKEN).unwrap().unwrap();
            assert_eq!(result["link_id"], persisted.id);
        } else {
            assert_eq!(result["unlinked"], true);
        }
        self.record(f, label, format!("<<{:?}, {}>>", project.label, tla_bool(confirmed)), None)
            .await;
    }

    async fn review(&mut self, f: &Fixture, expected: &[Project]) {
        let result = success(
            f.rpc(
                AgentMethod::ListSharedUsages,
                json!({"store_path": f.path, "target_secret_id": self.target}),
            )
            .await,
        );
        let usages = result["usages"].as_array().unwrap();
        assert_eq!(usages.len(), expected.len());
        let store = f.store();
        let mut ids = Vec::new();
        let mut projection = Vec::new();
        for usage in usages {
            let project =
                expected.iter().find(|project| usage["project_id"] == project.id).unwrap();
            let persisted =
                store.get_secret_link(project.id, project.profile, TOKEN).unwrap().unwrap();
            assert_eq!(usage["link_id"], persisted.id);
            assert_eq!(usage["target_secret_id"], self.target);
            assert_eq!(usage["local_name"], TOKEN);
            assert!(!ids.contains(&persisted.id));
            ids.push(persisted.id);
            projection.push(format!("<<{:?}, {}>>", project.label, self.unlink_count(f, *project)));
        }
        self.reviewed =
            Some(SharedUsageReview { ids, projection: format!("{{{}}}", projection.join(", ")) });
        self.record(f, "review", "<<>>", None).await;
    }

    async fn read(&mut self, f: &Fixture, project: Project, reveal: bool, expected: Option<&str>) {
        let (action, audit) = if reveal {
            (GrantAction::Reveal, "REVEAL")
        } else {
            (GrantAction::ResolveReference, "RESOLVE_REFERENCE")
        };
        let response = match f.grant(project, action, true).await {
            ResponseEnvelope::Error(error) => ResponseEnvelope::Error(error),
            ResponseEnvelope::Success(result) => {
                let id = result.payload["grant_id"].as_str().unwrap();
                if reveal {
                    let mut payload = f.scope(project, id);
                    payload["secret_name"] = json!(TOKEN);
                    f.rpc(AgentMethod::Reveal, payload).await
                } else {
                    f.resolve(project, id, "lk://default/TOKEN", &f.binding).await
                }
            }
        };
        let reader = match response {
            ResponseEnvelope::Success(result) => {
                assert_eq!(expected, None);
                assert_eq!(result.payload["value"], A_VALUE);
                let rows = f.audit_rows(project);
                let (_, _, metadata) =
                    rows.iter().rev().find(|(_, action, _)| action == audit).unwrap();
                assert_eq!(metadata["source"], "shared-link");
                Some(project)
            }
            ResponseEnvelope::Error(error) => {
                assert_eq!(Some(error.error.as_str()), expected);
                None
            }
        };
        self.record(
            f,
            "read",
            format!("<<{:?}, {}>>", project.label, tla_bool(reader.is_some())),
            reader,
        )
        .await;
    }

    async fn delete(
        &mut self,
        f: &Fixture,
        unlink_all: bool,
        confirmed: bool,
        expected: Result<u64, &str>,
    ) {
        let grant = f.grant_id(SHARED, GrantAction::DeleteSecret).await;
        let mut payload = f.scope(SHARED, &grant);
        payload["secret_name"] = json!(TOKEN);
        payload["source"] = json!("user-local");
        payload["unlink_all"] = json!(unlink_all);
        payload["confirmation"] = json!(confirmed.then_some("default"));
        if unlink_all {
            payload["expected_link_ids"] = json!(self.reviewed.as_ref().unwrap().ids);
        }
        let response = f.rpc(AgentMethod::DeleteSecret, payload).await;
        let accepted = match response {
            ResponseEnvelope::Success(result) => {
                assert_eq!(result.payload["unlinked_count"].as_u64(), Some(expected.unwrap()));
                assert_eq!(result.payload["deleted"], true);
                assert_eq!(
                    f.store().get_secret_by_id(&self.target).unwrap().unwrap().state,
                    "deleted"
                );
                true
            }
            ResponseEnvelope::Error(error) => {
                assert_eq!(error.error, expected.unwrap_err());
                if error.error == "UnlockRequired" {
                    assert!(error.message.contains(B.label));
                }
                false
            }
        };
        self.record(
            f,
            "delete",
            format!(
                "<<{}, {}, {}>>",
                tla_bool(unlink_all),
                tla_bool(confirmed),
                tla_bool(accepted)
            ),
            None,
        )
        .await;
    }
}

async fn publish_link_consumer(f: &Fixture, target_id: &str) {
    use locket_agent::team_sync;
    use locket_core::team_package::SignedStatement;

    let grant = f.grant_id(A, GrantAction::SetSecret).await;
    let mut payload = f.scope(A, &grant);
    payload["secret_name"] = json!("MANAGED_CONFIG");
    payload["source"] = json!("team-managed");
    payload["value"] = json!(B_VALUE);
    let managed = success(f.rpc(AgentMethod::SetSecret, payload).await);
    let store = &mut f.store();
    let managed_id = managed["secret_id"].as_str().unwrap();
    let tag: Vec<u8> = store
        .connection()
        .query_row(
            "SELECT dedup_tag FROM local_value_fingerprints WHERE secret_id = ?1 AND version = 1",
            [managed_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tag, locket_crypto::local_dedup_tag_v1(&FINGERPRINT_KEY, B_VALUE).unwrap());
    let link = store.get_secret_link(A.id, A.profile, TOKEN).unwrap().unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let owner = team_device("owner", &signer, &[32; 32]);
    let sealing = [33; 32];
    let recipient =
        team_device("recipient", &ed25519_dalek::SigningKey::from_bytes(&[34; 32]), &sealing);
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
    team_sync::add_recipient(
        store,
        A.id,
        &recipient,
        "recipient",
        "developer",
        &[A.profile.to_owned()],
        100,
    )
    .unwrap();
    assert_eq!(team_sync::publish(store, A.id, &A.master(), &signer, 101).unwrap(), 1);
    let ciphertext: Vec<u8> = store
        .connection()
        .query_row(
            "SELECT ciphertext FROM team_sync_outbox WHERE project_id = ?1 AND recipient = ?2",
            (A.id, &recipient.fingerprint),
            |row| row.get(0),
        )
        .unwrap();
    let package = SignedStatement::open(&ciphertext, &sealing).unwrap();
    let verified = package.verify(&owner.fingerprint, A.id, &recipient, 101).unwrap();
    assert_eq!(verified.statement.project_id, A.id);
    let [profile] = verified.statement.profiles.as_slice() else {
        panic!("expected one exported profile")
    };
    let [secret] = profile.secrets.as_slice() else { panic!("expected one team-managed secret") };
    assert_eq!(secret.id, managed_id);
    let signed_json = std::str::from_utf8(&package.statement).unwrap();
    for omitted in [
        "secret_links",
        "local_value_fingerprints",
        "dedup_tag",
        TOKEN,
        link.id.as_str(),
        target_id,
        &serde_json::to_string(&tag).unwrap(),
    ] {
        assert!(!signed_json.contains(omitted), "local-only data appeared in Team Sync");
    }
}

#[tokio::test]
async fn shared_secret_links() {
    let f = Fixture::new(&[(A, false), (B, true), (SHARED, false)]);
    let mut run = SharedLinksTrace::default();
    run.record(&f, "init", "<<>>", None).await;
    run.unlock(&f, SHARED).await;
    let writer = f.grant_id(SHARED, GrantAction::SetSecret).await;
    let created = success(f.set_secret(SHARED, &writer, "user-local", A_VALUE, None).await);
    run.target = created["secret_id"].as_str().unwrap().to_owned();
    run.record(&f, "create", "<<FALSE>>", None).await;
    run.lock(&f, SHARED).await;
    run.unlock(&f, A).await;
    run.mutate_link(&f, A, true, false).await;
    run.read(&f, A, false, Some("UnlockRequired")).await;
    run.review(&f, &[A]).await;
    run.unlock(&f, SHARED).await;
    run.read(&f, A, false, None).await;
    run.lock(&f, A).await;
    run.read(&f, A, false, Some("UnlockRequired")).await;
    run.unlock(&f, A).await;
    run.unlock(&f, B).await;
    run.mutate_link(&f, B, true, true).await;
    run.read(&f, B, true, None).await;
    run.delete(&f, false, true, Err("LinkedSecretInUse")).await;
    run.delete(&f, true, true, Err("LinkSetChanged")).await;
    run.review(&f, &[A, B]).await;
    run.mutate_link(&f, B, false, true).await;
    run.mutate_link(&f, B, true, true).await;
    run.delete(&f, true, true, Err("LinkSetChanged")).await;
    run.review(&f, &[A, B]).await;
    publish_link_consumer(&f, &run.target).await;
    run.published = true;
    run.record(&f, "publish", r#"<< "ProjA" >>"#, None).await;

    for (locked, action) in [(true, "nativeLock"), (false, "resume")] {
        f.state
            .lock_for_native_session_event(SessionLockSource::ScreenLock, locked, i128::from(now()))
            .await
            .unwrap();
        run.record(&f, action, "<<>>", None).await;
        if locked {
            run.read(&f, B, true, Some("UnlockRequired")).await;
        }
    }
    run.unlock(&f, SHARED).await;
    run.unlock(&f, A).await;
    run.delete(&f, true, true, Err("UnlockRequired")).await;
    run.unlock(&f, B).await;
    run.delete(&f, true, false, Err("ConfirmationFailed")).await;
    run.delete(&f, true, true, Ok(2)).await;
    run.read(&f, A, true, Some("SecretNotFound")).await;

    for project in [A, B, SHARED] {
        f.assert_audit_integrity(project);
    }
    assert_eq!([run.unlink_count(&f, A), run.unlink_count(&f, B)], [1, 2]);
    run.trace.emit("SharedSecretLinks");
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

async fn authorization_snapshot(fixture: &Fixture, outcome: &str, grant: Option<&str>) -> String {
    let unlocked =
        fixture.state.unlock_cache.lock().await.lookup(A.id, i128::from(now())).is_some();
    let blocked = fixture.session_blocked().await;
    let table = fixture.state.grants.lock().await;
    assert_eq!(table.len(), usize::from(grant.is_some()));
    let held = grant.is_some_and(|id| {
        let entry = table.get(id).unwrap();
        assert_eq!(entry.project_id, A.id);
        assert_eq!(entry.profile_id, A.profile);
        assert_eq!(entry.action, GrantAction::Reveal);
        true
    });
    format!(
        "[unlocked |-> {}, blocked |-> {}, grant |-> {}, outcome |-> {outcome:?}]",
        tla_bool(unlocked),
        tla_bool(blocked),
        tla_bool(held)
    )
}

#[tokio::test]
async fn agent_authorization_protocol() {
    use locket_agent::{PeerIdentity, dispatch_with_peer};
    use locket_platform::MemoryLocalUserVerifier;

    let mut fixture = Fixture::new(&[(A, true)]);
    fixture.state = fixture
        .state
        .with_daemon_user_verification(true)
        .with_user_verifier(Arc::new(MemoryLocalUserVerifier::allowing()));
    let denied =
        fixture.state.clone().with_user_verifier(Arc::new(MemoryLocalUserVerifier::denying()));
    fixture.state.master_key_store.store_master_key(A.id, &MASTER).unwrap();
    let live = locket_platform::current_process_binding().unwrap();
    let peer = PeerIdentity::new(current_process_uid(), Some(live.pid), 77);
    let binding = GrantBinding::new(live.pid, live.process_start_time);

    let mut trace = Trace::default();
    trace.record("init", "<<>>", &authorization_snapshot(&fixture, "none", None).await);
    let unlock = RequestEnvelope::new(
        "unlock",
        AgentMethod::Unlock,
        json!({
            "project_id": A.id, "ttl_seconds": 120,
            "audit": {"store_path": fixture.path, "profile_id": A.profile},
        }),
    );
    assert_eq!(
        denial(dispatch_with_peer(&unlock, &denied, Some(peer)).await),
        "UserVerificationFailed"
    );
    trace.record("unlock", "<<FALSE>>", &authorization_snapshot(&fixture, "Denied", None).await);
    success(dispatch_with_peer(&unlock, &fixture.state, Some(peer)).await);
    trace.record("unlock", "<<TRUE>>", &authorization_snapshot(&fixture, "Unlocked", None).await);

    let grant = |confirmed| {
        RequestEnvelope::new(
            "grant",
            AgentMethod::RequestGrant,
            json!({
                "project_id": A.id, "profile_id": A.profile, "store_path": fixture.path,
                "action": "Reveal", "confirm_dangerous": confirmed, "ttl_seconds": 30, "binding": binding,
            }),
        )
    };
    assert_eq!(
        denial(dispatch_with_peer(&grant(false), &fixture.state, Some(peer)).await),
        "ConfirmationFailed"
    );
    trace.record(
        "grant",
        "<<FALSE, TRUE>>",
        &authorization_snapshot(&fixture, "Denied", None).await,
    );

    let store = fixture.store();
    store
        .connection()
        .execute_batch(
            "CREATE TRIGGER deny_grant_audit BEFORE INSERT ON audit_log
         WHEN NEW.action = 'AGENT_GRANT' BEGIN SELECT RAISE(ABORT, 'trace fixture'); END",
        )
        .unwrap();
    assert_eq!(
        denial(dispatch_with_peer(&grant(true), &fixture.state, Some(peer)).await),
        "AuditIntegrityFailed"
    );
    trace.record(
        "grant",
        "<<TRUE, FALSE>>",
        &authorization_snapshot(&fixture, "AuditIntegrityFailed", None).await,
    );
    store.connection().execute_batch("DROP TRIGGER deny_grant_audit").unwrap();

    let id = grant_id(dispatch_with_peer(&grant(true), &fixture.state, Some(peer)).await);
    trace.record(
        "grant",
        "<<TRUE, TRUE>>",
        &authorization_snapshot(&fixture, "Granted", Some(&id)).await,
    );
    success(fixture.rpc(AgentMethod::Lock, json!({"project_id": A.id})).await);
    trace.record("lock", "<<>>", &authorization_snapshot(&fixture, "none", None).await);
    fixture.assert_audit_integrity(A);
    trace.emit("AgentAuthzProtocol");
}

fn signed_prepare(
    fixture: &Fixture,
    challenge: &locket_agent::ClientHelloResponse,
    signing: &ed25519_dalek::SigningKey,
) -> RequestEnvelope {
    use data_encoding::BASE64URL_NOPAD;
    use ed25519_dalek::Signer;

    let mut request = RequestEnvelope::new(
        "prepare",
        AgentMethod::PrepareExec,
        json!({
            "project_id": A.id, "profile_id": A.profile, "store_path": fixture.path,
            "policy_name": POLICY, "requested_action": "run-policy",
        }),
    );
    let timestamp = now();
    let mut canonical = serde_json::to_value(&request).unwrap();
    canonical.sort_all_objects();
    let digest = Sha256::digest(serde_json::to_vec(&canonical).unwrap());
    let nonce = BASE64URL_NOPAD.decode(challenge.nonce.as_bytes()).unwrap();
    let message = [
        b"locket-client-auth-v1",
        challenge.client_id.as_bytes(),
        challenge.challenge_id.as_bytes(),
        &nonce,
        timestamp.to_string().as_bytes(),
        request.id.as_bytes(),
        digest.as_slice(),
    ]
    .concat();
    request.payload["auth"] = json!({
        "client_id": challenge.client_id, "challenge_id": challenge.challenge_id,
        "nonce": challenge.nonce, "request_timestamp": timestamp,
        "signature": BASE64URL_NOPAD.encode(&signing.sign(&message).to_bytes()),
    });
    request
}

async fn automation_snapshot(
    fixture: &Fixture,
    nonce: Option<&str>,
    status: &str,
    granted: bool,
) -> String {
    use data_encoding::BASE64URL_NOPAD;

    let challenges = fixture.state.automation_challenges.lock().await.len();
    let store = fixture.store();
    let client = store.get_automation_client(A.id, "trace-client").unwrap();
    let registry = match &client {
        None => "absent",
        Some(row) if row.revoked_at.is_some() => "revoked",
        Some(_) => "active",
    };
    let last_used = tla_bool(client.and_then(|row| row.last_used_at).is_some());
    let mut query =
        store.connection().prepare("SELECT nonce FROM automation_client_nonces").unwrap();
    let stored = query
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    if !stored.is_empty() {
        assert_eq!(stored, [BASE64URL_NOPAD.decode(nonce.unwrap().as_bytes()).unwrap()]);
    }
    let used = if stored.is_empty() { "{}" } else { "{\"nonceA\"}" };
    let audit_count: u32 = store
        .connection()
        .query_row(
            "SELECT count(*) FROM audit_log WHERE action = 'CLIENT_AUTH' AND status = 'SUCCESS'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    format!(
        "[registry |-> {registry:?}, challenges |-> {challenges}, used |-> {used}, \
         auditCount |-> {audit_count}, lastUsed |-> {last_used}, status |-> {status:?}, granted |-> {}]",
        tla_bool(granted),
    )
}

#[tokio::test]
async fn automation_client_authentication() {
    use data_encoding::BASE64URL_NOPAD;
    use ed25519_dalek::SigningKey;
    use locket_agent::CommandPolicySnapshot;
    use locket_platform::MemoryLocalUserVerifier;

    let mut fixture = Fixture::new(&[(A, false)]);
    fixture.state = fixture
        .state
        .with_daemon_user_verification(true)
        .with_user_verifier(Arc::new(MemoryLocalUserVerifier::allowing()));
    success(fixture.unlock(A, 120).await);
    let policy = locket_core::PolicyDocument::from_toml_str(
        "schema_version = 1\n[commands.inspect]\nargv = ['echo']\nrequired_secrets = ['TOKEN']",
    )
    .unwrap();
    fixture.state.command_policies.lock().await.push(CommandPolicySnapshot::from_policy(
        A.id,
        &policy.commands[POLICY],
        1,
    ));
    let mut trace = Trace::default();
    trace.record("init", "<<>>", &automation_snapshot(&fixture, None, "none", false).await);
    let signing = SigningKey::from_bytes(&[23; 32]);
    let registration = success(fixture.rpc(AgentMethod::RegisterClient, json!({
        "project_id": A.id, "store_path": fixture.path, "name": "trace-client",
        "public_key": signing.verifying_key().to_bytes(), "storage": "external",
        "allowed_actions": ["run-policy", "resolve-reference"], "allowed_policies": [POLICY],
    })).await);
    let client = &registration["client_id"];
    trace.record("register", "<<>>", &automation_snapshot(&fixture, None, "none", false).await);

    let mut accepted_nonce: Option<String> = None;
    for (id, nonce_alias, expected) in [
        ("helloA", "nonceA", "Authenticated"),
        ("helloB", "nonceB", "Denied"),
        ("helloB", "nonceA", "Replay"),
    ] {
        let hello = fixture.rpc(AgentMethod::ClientHello, json!({"client_id": client})).await;
        let mut challenge: locket_agent::ClientHelloResponse =
            serde_json::from_value(success(hello)).unwrap();
        assert_eq!(client, &challenge.client_id);
        {
            let mut pool = fixture.state.automation_challenges.lock().await;
            let entry = pool.get_mut(&challenge.challenge_id).unwrap();
            assert_eq!(BASE64URL_NOPAD.encode(&entry.nonce), challenge.nonce);
            if expected == "Replay" {
                // Reissue a saved nonce under a new challenge id to exercise
                // the durable nonce table independently of challenge burning.
                challenge.nonce.clone_from(accepted_nonce.as_ref().unwrap());
                entry.nonce =
                    BASE64URL_NOPAD.decode(challenge.nonce.as_bytes()).unwrap().try_into().unwrap();
            }
            drop(pool);
        }
        trace.record(
            "hello",
            format!("<<{id:?}, {nonce_alias:?}>>"),
            &automation_snapshot(&fixture, accepted_nonce.as_deref(), "none", false).await,
        );
        let other = SigningKey::from_bytes(&[24; 32]);
        let signer = if expected == "Denied" { &other } else { &signing };
        let request = signed_prepare(&fixture, &challenge, signer);
        let response =
            locket_agent::dispatch_with_peer(&request, &fixture.state, Some(fixture.peer())).await;
        let granted = expected == "Authenticated";
        if granted {
            let id = grant_id(response);
            assert!(fixture.state.grants.lock().await.get(&id).is_some());
            accepted_nonce = Some(challenge.nonce);
            success(fixture.rpc(AgentMethod::RevokeGrant, json!({"grant_id": id})).await);
        } else {
            let error = if expected == "Replay" {
                "AutomationClientReplayDetected"
            } else {
                "AutomationClientNotTrusted"
            };
            assert_eq!(denial(response), error);
            assert!(fixture.state.grants.lock().await.is_empty());
        }
        let action = if expected == "Denied" { "badSignature" } else { "signed" };
        trace.record(
            action,
            format!("<<{id:?}, {nonce_alias:?}>>"),
            &automation_snapshot(&fixture, accepted_nonce.as_deref(), expected, granted).await,
        );
    }
    success(
        fixture
            .rpc(
                AgentMethod::RevokeClient,
                json!({
                    "project_id": A.id, "store_path": fixture.path, "client": client,
                }),
            )
            .await,
    );
    trace.record(
        "revoke",
        "<<>>",
        &automation_snapshot(&fixture, accepted_nonce.as_deref(), "none", false).await,
    );
    fixture.assert_audit_integrity(A);
    trace.emit("AutomationClientAuth");
}

#[cfg(unix)]
mod cli_traces {
    use super::{AgentMethod, RequestEnvelope, Store, Trace, fs, json, success, tla_bool};
    use locket_core::{ProfileId, ProjectId};
    use locket_platform::LocketInstance;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Output, Stdio};
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(10);

    fn tempdir() -> tempfile::TempDir {
        // Cargo wrappers may choose long temporary paths. Keep Unix socket
        // addresses within sockaddr_un and give the daemon a private parent.
        let root =
            std::env::var_os("LOCKET_TLA_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let dir = tempfile::tempdir_in(root).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn cli(root: &Path) -> Option<Command> {
        let binary = std::env::var_os("LOCKET_TLA_CLI").or_else(|| {
            assert!(
                std::env::var_os("LOCKET_TLA_TRACE_DIR").is_none(),
                "trace runner must supply the CLI"
            );
            None
        })?;
        let mut command = Command::new(binary);
        command
            .current_dir(root)
            .env("HOME", ".")
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_DATA_HOME", root.join("data"))
            .env("XDG_RUNTIME_DIR", ".")
            .env("LOCKET_INSTANCE", "dev")
            .stdin(Stdio::null());
        Some(command)
    }

    fn ok(output: Output) -> String {
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn serve(mut cli: Command, socket: &Path, pid: &Path) -> Command {
        cli.arg("internal-agent-serve").arg("--socket").arg(socket).arg("--pid-file").arg(pid);
        cli
    }

    struct Worker(Child);

    impl Drop for Worker {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    impl Worker {
        fn start(cli: &mut Command, socket: &Path, pid: &Path) -> Self {
            let mut worker = Self(cli.stdout(Stdio::null()).spawn().unwrap());
            let deadline = Instant::now() + WAIT;
            let expected_pid = worker.0.id().to_string();
            while fs::read_to_string(pid).map_or(true, |text| text.trim() != expected_pid) {
                assert!(
                    worker.0.try_wait().unwrap().is_none(),
                    "daemon exited before publishing its PID"
                );
                assert!(Instant::now() < deadline, "daemon did not publish its PID");
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(status(socket).is_object());
            worker
        }

        fn stop(&mut self) {
            use rustix::process::{Pid, Signal, kill_process};

            let pid = Pid::from_raw(i32::try_from(self.0.id()).unwrap()).unwrap();
            kill_process(pid, Signal::TERM).unwrap();
            let status = self.wait_for_exit();
            assert!(status.success(), "daemon exit: {status}");
        }

        fn wait_for_exit(&mut self) -> ExitStatus {
            let deadline = Instant::now() + WAIT;
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    return status;
                }
                assert!(Instant::now() < deadline, "daemon did not exit");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    fn status(socket: &Path) -> Value {
        use locket_agent::{DEFAULT_MAX_MESSAGE_SIZE, decode_response_frame, encode_frame};

        let mut stream = UnixStream::connect(socket).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream.set_write_timeout(Some(WAIT)).unwrap();
        let request = RequestEnvelope::new("status", AgentMethod::Status, Value::Null);
        stream.write_all(&encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE).unwrap()).unwrap();
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix).unwrap();
        let len = u32::from_le_bytes(prefix) as usize;
        assert!(len <= DEFAULT_MAX_MESSAGE_SIZE);
        let mut frame = prefix.to_vec();
        frame.resize(prefix.len() + len, 0);
        stream.read_exact(&mut frame[prefix.len()..]).unwrap();
        success(decode_response_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE).unwrap().0)
    }

    fn daemon_state(socket: &Path, pid: &Path, secondary_failed: bool) -> String {
        format!(
            "[socket |-> {}, pidFile |-> {}, secondaryFailed |-> {}]",
            tla_bool(socket.exists()),
            tla_bool(pid.exists()),
            tla_bool(secondary_failed)
        )
    }

    #[test]
    fn daemon_endpoint_lifecycle() {
        if cli(Path::new(".")).is_none() {
            return;
        }
        let root = tempdir();
        let Some(command) = cli(root.path()) else { return };
        let socket = root.path().join("daemon.sock");
        let pid = root.path().join("daemon.pid");
        let mut trace = Trace::default();
        trace.record("init", "<<>>", &daemon_state(&socket, &pid, false));

        let mut primary = Worker::start(&mut serve(command, &socket, &pid), &socket, &pid);
        trace.record("start", "<<>>", &daemon_state(&socket, &pid, false));
        let before = fs::metadata(&socket).unwrap().ino();
        let mut secondary = Worker(
            serve(cli(root.path()).unwrap(), &socket, &pid)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let secondary_failed = !secondary.wait_for_exit().success();
        assert!(secondary_failed);
        assert_eq!(fs::metadata(&socket).unwrap().ino(), before);
        assert_eq!(fs::read_to_string(&pid).unwrap().trim(), primary.0.id().to_string());
        assert!(status(&socket).is_object());
        trace.record("contend", "<<>>", &daemon_state(&socket, &pid, secondary_failed));

        primary.stop();
        trace.record("stop", "<<>>", &daemon_state(&socket, &pid, true));
        assert!(!socket.exists() && !pid.exists());
        trace.emit("AgentDaemonLifecycle");
    }

    fn initialize_egress_project(root: &Path, upstream: SocketAddr) -> (PathBuf, PathBuf) {
        let instance = LocketInstance::Dev;
        let dirs = instance.project_dirs().unwrap();
        let data_base = if cfg!(target_os = "macos") {
            root.join("Library/Application Support")
        } else {
            root.join("data")
        };
        let data = data_base.join(dirs.project_path());
        fs::create_dir_all(&data).unwrap();
        let mut store = Store::open(data.join("store.db")).unwrap();
        store.initialize_schema().unwrap();
        let project = ProjectId::generate().unwrap();
        let profile = ProfileId::generate().unwrap();
        store.insert_project_if_absent(project.as_str(), "trace-egress", 1).unwrap();
        store
            .insert_profile_if_absent(profile.as_str(), project.as_str(), "default", false, 1)
            .unwrap();
        let path = root.join("locket.toml");
        let program =
            serde_json::to_string(std::env::current_exe().unwrap().to_str().unwrap()).unwrap();
        let policy = format!(
            r#"
schema_version = 1
project_id = "{project}"
name = "trace-egress"
default_profile = "default"
[commands.probe]
argv = [{program}, "--exact", "cli_traces::egress_probe_child", "--nocapture"]
required_secrets = ["TOKEN"]
external_env_sources = [{{file = ".settings"}}]
env_mode = "strict"
"#,
        );
        fs::write(&path, &policy).unwrap();
        fs::write(root.join(".settings"), "TOKEN=synthetic-egress-trace-token\n").unwrap();
        fs::write(root.join(".trace-egress-upstream"), upstream.to_string()).unwrap();
        let root_text = root.to_str().unwrap();
        store
            .trust_project_root(
                project.as_str(),
                &Sha256::digest(root_text).into(),
                Some(root_text),
                1,
            )
            .unwrap();
        let doc: toml::Value = toml::from_str(&policy).unwrap();
        let digest = locket_core::policy::policy_source_digest(&doc, "probe").unwrap();
        store
            .upsert_command_policy_index(
                project.as_str(),
                "probe",
                &json!(doc["commands"]["probe"]),
                &json!({"source_path": path, "source_digest": digest}),
                1,
                None,
            )
            .unwrap();
        let agent = instance.agent_data_dir(std::env::consts::OS, root, Some(root.as_os_str()));
        (agent.join("agent.sock"), agent.join("agent.pid"))
    }

    #[test]
    fn egress_probe_child() {
        let Ok(target) = fs::read_to_string(".trace-egress-upstream") else { return };
        let proxy = std::env::var("HTTP_PROXY").unwrap();
        let (credentials, address) =
            proxy.strip_prefix("http://").unwrap().split_once('@').unwrap();
        let address: SocketAddr = address.parse().unwrap();
        assert!(address.ip().is_loopback());
        let token = std::env::var("TOKEN").unwrap();
        assert_ne!(token, "synthetic-egress-trace-token");
        let auth = data_encoding::BASE64.encode(credentials.as_bytes());
        for (label, header) in [
            ("missing", String::new()),
            ("valid", format!("Proxy-Authorization: Basic {auth}\r\n")),
        ] {
            let mut stream = TcpStream::connect_timeout(&address, WAIT).unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            stream.set_write_timeout(Some(WAIT)).unwrap();
            write!(stream,
                "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nAuthorization: Bearer {token}\r\n{header}\r\n"
            ).unwrap();
            let mut status = String::new();
            BufReader::new(stream).read_line(&mut status).unwrap();
            writeln!(std::io::stdout().lock(), "{label}: {}", status.trim_end()).unwrap();
        }
    }

    #[test]
    fn egress_authentication_and_destination_screening() {
        if cli(Path::new(".")).is_none() {
            return;
        }
        let dir = tempdir();
        let root = dir.path().canonicalize().unwrap();
        let Some(mut command) = cli(&root) else { return };
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let (socket, pid) = initialize_egress_project(&root, upstream.local_addr().unwrap());
        let mut worker =
            Worker::start(&mut serve(cli(&root).unwrap(), &socket, &pid), &socket, &pid);
        // The fixture has no OS keychain entry. The later run-policy audit
        // can fail after the child and broker have already finished.
        let output = command
            .args([
                "run",
                "--egress-host",
                "TOKEN=127.0.0.1",
                "--no-egress-tls-mitm",
                "--allow-uncontained-egress",
                "probe",
            ])
            .output()
            .unwrap();
        let diagnostics = String::from_utf8(output.stderr).unwrap();
        assert!(diagnostics.contains("Locket blocked 2 egress request(s)"), "{diagnostics}");
        let transcript = String::from_utf8(output.stdout).unwrap();
        assert!(transcript.contains("test result: ok. 1 passed"), "{transcript}");
        let forwarded = match upstream.accept() {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(error) => panic!("could not check for upstream connections: {error}"),
        };
        assert!(!forwarded);
        let trace_for = |auth: &str, status: &str| {
            assert!(transcript.lines().any(|line| line == status), "{transcript}");
            let mut trace = Trace::default();
            trace.record("init", "<<>>", r#"[phase |-> "start", forwarded |-> FALSE]"#);
            trace.record(
                "request",
                format!("<<{auth:?}>>"),
                &format!(r#"[phase |-> "rejected", forwarded |-> {}]"#, tla_bool(forwarded)),
            );
            trace
        };
        let screened = trace_for("valid", "valid: HTTP/1.1 403 Forbidden");
        let unauthenticated =
            trace_for("missing", "missing: HTTP/1.1 407 Proxy Authentication Required");
        worker.stop();
        screened.emit_with_rejection("EgressProxyAndRedaction", Some(unauthenticated));
    }

    fn inspect(root: &Path, path: &str) -> (bool, Value) {
        let mut child = cli(root)
            .unwrap()
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
            child.stdin.take().unwrap(),
            "{}",
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "locket_inspect_env_keys", "arguments": {"path": path}},
            })
        )
        .unwrap();
        let response: Value = serde_json::from_str(&ok(child.wait_with_output().unwrap())).unwrap();
        let result = &response["result"];
        let content = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        (result["isError"].as_bool().unwrap(), content)
    }

    #[test]
    fn mcp_env_file_boundary() {
        use std::os::unix::fs::symlink;

        if cli(Path::new(".")).is_none() {
            return;
        }
        let home = tempdir();
        let root = home.path().join("workspace");
        fs::create_dir(&root).unwrap();
        fs::write(root.join(".env"), "TOKEN=synthetic-mcp-plaintext\n").unwrap();
        let external = home.path().join(".outside");
        fs::write(&external, "PRIVATE_OUTSIDE=synthetic-outside-plaintext\n").unwrap();
        symlink(external, root.join(".link")).unwrap();

        let observed = |path: &str, is_link: bool| {
            let (failed, content) = inspect(&root, path);
            let response = content.to_string();
            assert_eq!(failed, is_link, "{response}");
            assert!(!response.contains("synthetic-outside-plaintext"));
            assert!(!response.contains("PRIVATE_OUTSIDE"));
            let mut fields = Vec::new();
            if content["keys"].as_array().is_some_and(|keys| keys.iter().any(|key| key == "TOKEN"))
            {
                fields.push(r#""secret-name""#);
            }
            if response.contains("synthetic-mcp-plaintext") {
                fields.push(r#""plaintext-secret""#);
            }
            let mut trace = Trace::default();
            trace.record("init", "<<>>", "[phase |-> \"idle\", response |-> {}]");
            trace.record(
                "inspect",
                format!("<<{}>>", tla_bool(is_link)),
                &format!("[phase |-> \"done\", response |-> {{{}}}]", fields.join(", ")),
            );
            trace
        };
        observed(".env", false)
            .emit_with_rejection("McpAndDesktopBoundary", Some(observed(".link", true)));
    }
}
