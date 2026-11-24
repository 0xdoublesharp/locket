//! Live dispatcher projection of AgentUnlockGrantLifecycle.tla: locked
//! projects fail closed, grants stay scoped, and automation redemption is unique.

use std::path::PathBuf;
use std::sync::Arc;

use locket_crypto::{
    HkdfWrapInfo, KeyBytes, KeyPurpose, KeyWrapAad, derive_wrapping_key_v1, key_wrap_aad_v1,
    wrap_key_material_v1,
};
use locket_platform::MemoryLocalUserVerifier;
use locket_store::{KeyRecord, Store};
use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::TestCaseResult;
use serde_json::{Value, json};

use super::{auth_now_i64, insert_wrapped_audit_key, sign_auth_payload};
use crate::{
    AgentMethod, AgentSocketState, CommandPolicySnapshot, GrantAction, GrantBinding, PeerIdentity,
    RequestEnvelope, ResponseEnvelope, dispatch_with_peer,
};

const PROJECT: &str = "lk_proj_conformance";
const MASTER: KeyBytes = [42; 32];
const AUDIT: KeyBytes = [11; 32];
const SECRET: &str = "API_KEY";
type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scope {
    dangerous: bool,
    other_policy: bool,
}

impl Scope {
    const DEV: Self = Self { dangerous: false, other_policy: false };

    const fn profile(self) -> &'static str {
        if self.dangerous { "prod" } else { "dev" }
    }

    const fn policy(self) -> &'static str {
        if self.other_policy { "policy-b" } else { "policy-a" }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Binding {
    Owner,
    OtherPeer,
    ChangedStart,
}

#[derive(Clone, Copy, Debug)]
enum WhichGrant {
    Latest,
    Issued(Index),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Credential {
    Local(bool),
    Fresh,
    ReplayChallenge,
    ReplayNonce,
}

#[derive(Clone, Copy, Debug)]
enum Step {
    Unlock(bool),
    Register(bool),
    Grant(GrantAction, Scope, bool, Binding, bool),
    Prepare(Scope, bool, Credential),
    Resolve(WhichGrant, Scope, Binding),
    Revoke(WhichGrant),
    Age(WhichGrant),
    Expire(WhichGrant),
    Lock,
    RevokeClient,
}

fn steps() -> impl Strategy<Value = Step> {
    let scope = || {
        (any::<bool>(), any::<bool>())
            .prop_map(|(dangerous, other_policy)| Scope { dangerous, other_policy })
    };
    let binding = || {
        prop_oneof![4 => Just(Binding::Owner), 1 => Just(Binding::OtherPeer),
        1 => Just(Binding::ChangedStart)]
    };
    let which =
        || prop_oneof![Just(WhichGrant::Latest), any::<Index>().prop_map(WhichGrant::Issued)];
    let action = prop::sample::select(vec![
        GrantAction::Reveal,
        GrantAction::Copy,
        GrantAction::Export,
        GrantAction::ResolveReference,
        GrantAction::PrepareExec,
        GrantAction::ScanKnownValues,
        GrantAction::TeamSync,
    ]);
    let credential = prop_oneof![
        any::<bool>().prop_map(Credential::Local),
        Just(Credential::Fresh),
        Just(Credential::ReplayChallenge),
        Just(Credential::ReplayNonce),
    ];
    prop_oneof![
        3 => any::<bool>().prop_map(Step::Unlock),
        2 => any::<bool>().prop_map(Step::Register),
        6 => (action, scope(), any::<bool>(), binding(), any::<bool>())
            .prop_map(|(action, scope, confirmed, binding, allow)| Step::Grant(action, scope, confirmed, binding, allow)),
        6 => (scope(), any::<bool>(), credential)
            .prop_map(|(scope, confirmed, credential)| Step::Prepare(scope, confirmed, credential)),
        6 => (which(), scope(), binding()).prop_map(|(which, scope, binding)| Step::Resolve(which, scope, binding)),
        2 => which().prop_map(Step::Revoke),
        2 => which().prop_map(Step::Age),
        2 => which().prop_map(Step::Expire),
        2 => Just(Step::Lock),
        2 => Just(Step::RevokeClient),
    ]
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    allow: AgentSocketState,
    deny: AgentSocketState,
    owner: GrantBinding,
}

impl Fixture {
    async fn new() -> Result<(Self, Store), TestCaseError> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store.db");
        let mut store = Store::open(&path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT, "authorization conformance", 1)?;
        insert_wrapped_audit_key(&store, PROJECT, &MASTER, &AUDIT).map_err(failure)?;
        for (profile, dangerous) in [("dev", false), ("prod", true)] {
            store.insert_profile_if_absent(profile, PROJECT, profile, dangerous, 1)?;
            seed_profile_key(&store, profile, KeyPurpose::ProfileSecret, &[12; 32])
                .map_err(failure)?;
            seed_profile_key(&store, profile, KeyPurpose::ProfileFingerprint, &[13; 32])
                .map_err(failure)?;
        }
        let allow = AgentSocketState::locked("authz-conformance")
            .with_canonical_store_path(path.clone())
            .with_daemon_user_verification(true)
            .with_user_verifier(Arc::new(MemoryLocalUserVerifier::allowing()));
        let deny = allow.clone().with_user_verifier(Arc::new(MemoryLocalUserVerifier::denying()));
        allow.seed_master_key(PROJECT, &MASTER)?;
        let policies = install_policies(&mut store, directory.path()).map_err(failure)?;
        allow.set_command_policies_for_tests(policies).await;
        let owner = locket_platform::current_process_binding()?;
        let owner = GrantBinding::new(owner.pid, owner.process_start_time);
        let fixture = Self { _directory: directory, path, allow, deny, owner };
        fixture.seed_secrets().await?;
        Ok((fixture, store))
    }

    async fn seed_secrets(&self) -> Result<(), TestCaseError> {
        self.require_ok(AgentMethod::Unlock, json!({"ttl_seconds": 120})).await?;
        for dangerous in [false, true] {
            let scope = Scope { dangerous, ..Scope::DEV };
            let grant = self.require_ok(AgentMethod::RequestGrant, json!({
                "action": GrantAction::SetSecret, "profile_id": scope.profile(), "confirm_dangerous": true,
                "ttl_seconds": 60, "binding": self.owner,
            })).await?;
            self.require_ok(
                AgentMethod::SetSecret,
                json!({
                    "profile_id": scope.profile(), "grant_id": field(&grant, "grant_id")?,
                    "binding": self.owner, "secret_name": SECRET, "value": secret_value(scope),
                }),
            )
            .await?;
        }
        self.require_ok(AgentMethod::Lock, json!({})).await?;
        Ok(())
    }

    fn request(&self, id: &str, method: AgentMethod, mut payload: Value) -> RequestEnvelope {
        payload["project_id"] = json!(PROJECT);
        payload["store_path"] = json!(self.path);
        RequestEnvelope::new(id, method, payload)
    }

    async fn dispatch(
        &self,
        request: &RequestEnvelope,
        binding: Binding,
        allow: bool,
    ) -> ResponseEnvelope {
        let state = if allow { &self.allow } else { &self.deny };
        let pid = if binding == Binding::OtherPeer { self.owner.pid ^ 1 } else { self.owner.pid };
        let peer = PeerIdentity { uid: state.daemon_uid, pid: Some(pid), connection_id: 77 };
        dispatch_with_peer(request, state, Some(peer)).await
    }

    fn claimed_binding(&self, binding: Binding) -> GrantBinding {
        if binding == Binding::ChangedStart {
            GrantBinding::new(self.owner.pid, "changed-start-time")
        } else {
            self.owner.clone()
        }
    }

    async fn require_ok(
        &self,
        method: AgentMethod,
        payload: Value,
    ) -> Result<Value, TestCaseError> {
        let request = self.request("fixture", method, payload);
        check(self.dispatch(&request, Binding::Owner, true).await, true)
    }

    async fn sign(
        &self,
        request: &mut RequestEnvelope,
        client: Option<&Client>,
        previous_nonce: Option<&str>,
    ) -> Result<(), TestCaseError> {
        let client_id = client.map_or("missing-client", |client| client.id.as_str());
        let hello =
            self.require_ok(AgentMethod::ClientHello, json!({"client_id": client_id})).await?;
        let challenge_id = field(&hello, "challenge_id")?;
        let nonce = if let Some(previous) = previous_nonce {
            // Keep a fresh challenge ID while simulating a repeated RNG
            // value, so the persistent nonce guard is tested independently.
            let decoded =
                data_encoding::BASE64URL_NOPAD.decode(previous.as_bytes()).map_err(failure)?;
            let mut challenges = self.allow.automation_challenges.lock().await;
            let challenge = challenges
                .get_mut(challenge_id)
                .ok_or_else(|| TestCaseError::fail("minted challenge missing"))?;
            challenge.nonce = decoded
                .try_into()
                .map_err(|_| TestCaseError::fail("invalid challenge nonce length"))?;
            drop(challenges);
            previous
        } else {
            field(&hello, "nonce")?
        };
        request.payload["auth"] = sign_auth_payload(
            &signing_key(client.map_or(0, |client| client.key_byte)),
            request,
            client_id,
            challenge_id,
            nonce,
            auth_now_i64(),
        )
        .map_err(failure)?;
        Ok(())
    }
}

fn seed_profile_key(
    store: &Store,
    profile: &str,
    purpose: KeyPurpose,
    material: &KeyBytes,
) -> FixtureResult<()> {
    let id = format!("lk_key_{profile}_{}", purpose.as_str());
    let wrapping =
        derive_wrapping_key_v1(&MASTER, &HkdfWrapInfo::new(PROJECT, Some(profile), purpose))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(PROJECT, &id, Some(profile), 0, purpose.into()))?;
    let wrapped = wrap_key_material_v1(&wrapping, material, &aad)?;
    store.insert_key(&KeyRecord {
        id,
        project_id: PROJECT.to_owned(),
        profile_id: Some(profile.to_owned()),
        purpose: purpose.as_str().to_owned(),
        wrapped_material: wrapped.ciphertext,
        nonce: wrapped.nonce,
        created_at: 1,
    })?;
    Ok(())
}

fn install_policies(
    store: &mut Store,
    root: &std::path::Path,
) -> FixtureResult<Vec<CommandPolicySnapshot>> {
    let path = root.join("locket.toml");
    let policy = json!({"argv": ["fixture"], "required_secrets": [SECRET]});
    let document = toml::Value::try_from(json!({
        "schema_version": 1, "project_id": PROJECT, "default_profile": "dev",
        "commands": {"policy-a": policy, "policy-b": policy},
    }))?;
    std::fs::write(&path, toml::to_string(&document)?)?;
    let mut snapshots = Vec::new();
    for name in ["policy-a", "policy-b"] {
        store.upsert_command_policy_index(
            PROJECT,
            name,
            &policy,
            &json!({
                "schema_version": 1, "name": name, "source_path": path,
                "source_digest": locket_core::policy::policy_source_digest(&document, name)?,
            }),
            1,
            None,
        )?;
        snapshots.push(CommandPolicySnapshot {
            project_id: PROJECT.into(),
            name: name.into(),
            command_kind: "argv".into(),
            command_preview: "fixture".into(),
            required_secrets: vec![SECRET.into()],
            optional_secrets: vec![],
            allowed_secrets: vec![SECRET.into()],
            confirm: false,
            require_user_verification: false,
            require_agent: true,
            allow_remote_docker: false,
            ttl_seconds: 60,
            env_mode: "minimal".into(),
            override_mode: "locket".into(),
            updated_at_unix_nanos: 1,
        });
    }
    Ok(snapshots)
}

const fn secret_value(scope: Scope) -> &'static str {
    if scope.dangerous { "synthetic-prod-value" } else { "synthetic-dev-value" }
}

fn failure(error: impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, TestCaseError> {
    value[name].as_str().ok_or_else(|| TestCaseError::fail(format!("missing {name}")))
}

fn check(response: ResponseEnvelope, expected: bool) -> Result<Value, TestCaseError> {
    match response {
        ResponseEnvelope::Success(response) if expected => Ok(response.payload),
        ResponseEnvelope::Error(error) if !expected => {
            prop_assert!(
                !matches!(
                    error.error.as_str(),
                    "ProtocolError" | "CorruptDb" | "AuditIntegrityFailed"
                ) || error.message == "grant is still live",
                "unexpected failure: {:?}",
                error
            );
            Ok(Value::Null)
        }
        response => {
            Err(TestCaseError::fail(format!("expected success={expected}, got {response:?}")))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantState {
    Live,
    Expired,
    Removed,
}

struct IssuedGrant {
    id: String,
    scope: Scope,
    action: GrantAction,
    confirmed: bool,
    state: GrantState,
}

struct Client {
    id: String,
    key_byte: u8,
    revoked: bool,
}

fn signing_key(key_byte: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[key_byte; 32])
}

#[derive(Default)]
struct Model {
    unlocked: bool,
    grants: Vec<IssuedGrant>,
    client: Option<Client>,
    registrations: i64,
    last_redemption: Option<RequestEnvelope>,
    redemptions: i64,
}

impl Model {
    fn select(&self, which: WhichGrant) -> Option<usize> {
        if self.grants.is_empty() {
            return None;
        }
        Some(match which {
            WhichGrant::Latest => self.grants.len() - 1,
            WhichGrant::Issued(index) => index.index(self.grants.len()),
        })
    }

    fn record_grant(
        &mut self,
        response: &Value,
        scope: Scope,
        action: GrantAction,
        confirmed: bool,
    ) -> TestCaseResult {
        self.grants.push(IssuedGrant {
            id: field(response, "grant_id")?.to_owned(),
            scope,
            action,
            confirmed,
            state: GrantState::Live,
        });
        Ok(())
    }

    async fn prepare(
        &mut self,
        fixture: &Fixture,
        id: &str,
        scope: Scope,
        confirmed: bool,
        credential: Credential,
    ) -> TestCaseResult {
        let mut request = fixture.request(
            id,
            AgentMethod::PrepareExec,
            json!({
                "profile_id": scope.profile(), "policy_name": scope.policy(),
                "confirm_dangerous": confirmed, "binding": fixture.owner,
                "requested_action": "run-policy",
            }),
        );
        let (allow, redeemed) = match credential {
            Credential::Local(allow) => (allow, false),
            Credential::Fresh | Credential::ReplayNonce => {
                let client =
                    self.client.as_ref().map_or("missing-client", |client| client.id.as_str());
                let previous = self.last_redemption.as_ref().filter(|previous| {
                    credential == Credential::ReplayNonce
                        && previous.payload["auth"]["client_id"] == client
                });
                let nonce = previous.map(|req| field(&req.payload["auth"], "nonce")).transpose()?;
                if credential == Credential::ReplayNonce && nonce.is_none() {
                    return Ok(());
                }
                fixture.sign(&mut request, self.client.as_ref(), nonce).await?;
                let redeemed = self.unlocked
                    && !scope.other_policy
                    && nonce.is_none()
                    && self.client.as_ref().is_some_and(|client| !client.revoked);
                (false, redeemed)
            }
            Credential::ReplayChallenge => {
                let Some(previous) = &self.last_redemption else { return Ok(()) };
                request = previous.clone();
                (false, false)
            }
        };
        let expected = self.unlocked && (!scope.dangerous || confirmed) && (allow || redeemed);
        let response = check(fixture.dispatch(&request, Binding::Owner, allow).await, expected)?;
        if redeemed {
            self.redemptions += 1;
            self.last_redemption = Some(request);
        }
        if expected {
            self.record_grant(&response, scope, GrantAction::PrepareExec, confirmed)?;
        }
        Ok(())
    }

    async fn use_grant(
        &mut self,
        fixture: &Fixture,
        id: &str,
        step: Step,
        which: WhichGrant,
    ) -> TestCaseResult {
        let index = self.select(which);
        let grant = index.map(|index| &self.grants[index]);
        let grant_id = grant.map_or("missing-grant", |grant| &grant.id);
        let status = grant.map_or(GrantState::Removed, |grant| grant.state);
        let (method, payload, binding, expected) = match step {
            Step::Resolve(_, scope, binding) => {
                let expected = self.unlocked
                    && binding == Binding::Owner
                    && grant.is_some_and(|grant| {
                        grant.state == GrantState::Live
                            && grant.scope == scope
                            && matches!(
                                grant.action,
                                GrantAction::ResolveReference | GrantAction::PrepareExec
                            )
                    });
                (
                    AgentMethod::ResolveReference,
                    json!({
                        "reference": format!("lk://{}/{SECRET}", scope.profile()),
                        "profile_id": scope.profile(), "policy_name": scope.policy(), "grant_id": grant_id,
                        "binding": fixture.claimed_binding(binding),
                    }),
                    binding,
                    expected,
                )
            }
            Step::Revoke(_) => (
                AgentMethod::RevokeGrant,
                json!({"grant_id": grant_id}),
                Binding::Owner,
                status != GrantState::Removed,
            ),
            Step::Expire(_) => (
                AgentMethod::ExpireGrant,
                json!({"grant_id": grant_id}),
                Binding::Owner,
                status != GrantState::Live,
            ),
            Step::Age(_) => {
                if let Some(index) = index
                    && status == GrantState::Live
                {
                    // Advance only this record's deadline. Real-time waits
                    // would make shrinking slow and the outcome timing-dependent.
                    let mut table = fixture.allow.grants.lock().await;
                    let mut record = table
                        .get(grant_id)
                        .cloned()
                        .ok_or_else(|| TestCaseError::fail("grant missing before expiry"))?;
                    record.expires_at_unix_nanos = crate::server::current_unix_nanos() - 1;
                    table.insert(record);
                    drop(table);
                    self.grants[index].state = GrantState::Expired;
                }
                return Ok(());
            }
            _ => return Err(TestCaseError::fail("invalid use-grant transition")),
        };
        let request = fixture.request(id, method, payload);
        let response = check(fixture.dispatch(&request, binding, true).await, expected)?;
        if expected {
            if let Step::Resolve(_, scope, _) = step {
                prop_assert_eq!(response["value"].as_str(), Some(secret_value(scope)));
                prop_assert_eq!(response["profile_id"].as_str(), Some(scope.profile()));
            } else if let Some(index) = index {
                self.grants[index].state = GrantState::Removed;
            }
        }
        Ok(())
    }

    async fn step(&mut self, fixture: &Fixture, index: usize, step: Step) -> TestCaseResult {
        let id = format!("step-{index}");
        let key_byte = u8::try_from(index).map_err(failure)?;
        let (method, payload, binding, allow, expected) = match step {
            Step::Unlock(allow) => {
                (AgentMethod::Unlock, json!({"ttl_seconds": 120}), Binding::Owner, allow, allow)
            }
            Step::Lock => (AgentMethod::Lock, json!({}), Binding::Owner, true, true),
            Step::Register(allow) => (
                AgentMethod::RegisterClient,
                json!({
                    "name": format!("fixture-{index}"), "storage": "external",
                    "public_key": signing_key(key_byte).verifying_key().to_bytes(),
                    "allowed_actions": ["run-policy"], "allowed_policies": ["policy-a"],
                }),
                Binding::Owner,
                allow,
                self.unlocked && allow,
            ),
            Step::RevokeClient => (
                AgentMethod::RevokeClient,
                json!({
                    "client": self.client.as_ref().map_or("missing-client", |client| client.id.as_str()),
                }),
                Binding::Owner,
                true,
                self.unlocked && self.client.is_some(),
            ),
            Step::Grant(action, scope, confirmed, binding, allow) => (
                AgentMethod::RequestGrant,
                json!({
                    "profile_id": scope.profile(), "policy_name": scope.policy(), "action": action,
                    "confirm_dangerous": confirmed, "ttl_seconds": 60,
                    "binding": fixture.claimed_binding(binding),
                }),
                binding,
                allow,
                self.unlocked
                    && allow
                    && binding == Binding::Owner
                    && (!scope.dangerous || confirmed),
            ),
            Step::Prepare(scope, confirmed, credential) => {
                return self.prepare(fixture, &id, scope, confirmed, credential).await;
            }
            Step::Resolve(which, ..)
            | Step::Revoke(which)
            | Step::Age(which)
            | Step::Expire(which) => return self.use_grant(fixture, &id, step, which).await,
        };
        let request = fixture.request(&id, method, payload);
        let response = check(fixture.dispatch(&request, binding, allow).await, expected)?;
        if expected {
            match step {
                Step::Unlock(_) => self.unlocked = true,
                Step::Lock => {
                    self.unlocked = false;
                    for grant in &mut self.grants {
                        grant.state = GrantState::Removed;
                    }
                }
                Step::Register(_) => {
                    self.client = Some(Client {
                        id: field(&response, "client_id")?.to_owned(),
                        key_byte,
                        revoked: false,
                    });
                    self.registrations += 1;
                }
                Step::RevokeClient => {
                    if let Some(client) = &mut self.client {
                        client.revoked = true;
                    }
                }
                Step::Grant(action, scope, confirmed, ..) => {
                    self.record_grant(&response, scope, action, confirmed)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn check_state(&self, fixture: &Fixture) -> TestCaseResult {
        let now = crate::server::current_unix_nanos();
        let cache_live = fixture.allow.unlock_cache.lock().await.lookup(PROJECT, now).is_some();
        prop_assert_eq!(cache_live, self.unlocked);
        let table = fixture.allow.grants.lock().await;
        let mut retained = 0;
        for grant in &self.grants {
            if grant.state == GrantState::Removed {
                prop_assert!(table.get(&grant.id).is_none(), "removed grant is still present");
                continue;
            }
            retained += 1;
            let record =
                table.get(&grant.id).ok_or_else(|| TestCaseError::fail("grant missing"))?;
            prop_assert!(self.unlocked && (!grant.scope.dangerous || grant.confirmed));
            prop_assert_eq!(&record.project_id, PROJECT);
            prop_assert_eq!(&record.profile_id, grant.scope.profile());
            prop_assert_eq!(record.policy_name.as_deref(), Some(grant.scope.policy()));
            prop_assert_eq!(record.action, grant.action);
            prop_assert_eq!(&record.binding, &fixture.owner);
            prop_assert_eq!(record.observed_peer_pid, Some(fixture.owner.pid));
            prop_assert_eq!(record.expires_at_unix_nanos > now, grant.state == GrantState::Live);
        }
        prop_assert_eq!(table.len(), retained);
        drop(table);
        Ok(())
    }

    fn check_store(&self, store: &Store) -> TestCaseResult {
        if let Some(client) = &self.client {
            let stored = store
                .get_automation_client(PROJECT, &client.id)
                .map_err(failure)?
                .ok_or_else(|| TestCaseError::fail("registered client missing"))?;
            prop_assert_eq!(stored.revoked_at.is_some(), client.revoked);
        }
        let (successes, nonces, registered): (i64, i64, i64) = store.connection().query_row(
            "SELECT (SELECT count(*) FROM audit_log WHERE action = 'CLIENT_AUTH' AND status = 'SUCCESS'),
                    (SELECT count(*) FROM automation_client_nonces),
                    (SELECT count(*) FROM automation_clients)",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).map_err(failure)?;
        prop_assert_eq!(successes, self.redemptions, "unexpected authentication audit");
        prop_assert_eq!(nonces, self.redemptions, "unexpected persisted nonce redemption");
        prop_assert_eq!(registered, self.registrations, "unexpected client registration");
        Ok(())
    }
}

#[tokio::test]
async fn authorization_trace_exercises_success_and_each_denial() -> TestCaseResult {
    use Binding::{ChangedStart, OtherPeer, Owner};
    use Credential::{Fresh, Local, ReplayChallenge, ReplayNonce};
    use Step::{
        Age, Expire, Grant, Lock, Prepare, Register, Resolve, Revoke, RevokeClient, Unlock,
    };
    use WhichGrant::Latest;

    let dev = Scope::DEV;
    let prod = Scope { dangerous: true, ..dev };
    let other = Scope { other_policy: true, ..dev };
    // A positive witness precedes each denial so randomly sampled runs
    // cannot pass by leaving the vault locked or by never acquiring a grant.
    let trace = [
        Unlock(false),
        Grant(GrantAction::Reveal, dev, true, Owner, true),
        Unlock(true),
        Register(false),
        Register(true),
        Grant(GrantAction::ResolveReference, dev, true, ChangedStart, true),
        Grant(GrantAction::ResolveReference, dev, true, OtherPeer, true),
        Grant(GrantAction::ResolveReference, prod, false, Owner, true),
        Prepare(prod, false, Local(true)),
        Prepare(dev, true, Local(false)),
        Prepare(other, true, Fresh),
        Prepare(prod, false, Fresh),
        Prepare(dev, true, Fresh),
        Resolve(Latest, dev, Owner),
        Resolve(Latest, other, Owner),
        Resolve(Latest, dev, OtherPeer),
        Resolve(Latest, dev, ChangedStart),
        Resolve(Latest, prod, Owner),
        Prepare(dev, true, ReplayChallenge),
        Prepare(dev, true, ReplayNonce),
        Expire(Latest),
        Age(Latest),
        Resolve(Latest, dev, Owner),
        Expire(Latest),
        Resolve(Latest, dev, Owner),
        Prepare(prod, true, Local(true)),
        Resolve(Latest, prod, Owner),
        Revoke(Latest),
        Resolve(Latest, prod, Owner),
        Prepare(other, true, Local(true)),
        Resolve(Latest, other, Owner),
        Resolve(Latest, dev, Owner),
        Lock,
        Resolve(Latest, other, Owner),
        Unlock(true),
        Resolve(Latest, other, Owner),
        Prepare(dev, true, Fresh),
        RevokeClient,
        Prepare(dev, true, Fresh),
        Prepare(dev, true, ReplayChallenge),
    ];
    run_trace(trace.into_iter()).await
}

async fn run_trace(trace: impl Iterator<Item = Step> + Send) -> TestCaseResult {
    let (fixture, store) = Fixture::new().await?;
    let mut model = Model::default();
    for (index, step) in trace.enumerate() {
        model
            .step(&fixture, index, step)
            .await
            .map_err(|error| failure(format!("transition {index} {step:?}: {error}")))?;
        model
            .check_state(&fixture)
            .await
            .and_then(|()| model.check_store(&store))
            .map_err(|error| failure(format!("after transition {index} {step:?}: {error}")))?;
    }
    let audit = store.verify_audit_chain_read_only(PROJECT, &AUDIT).map_err(failure)?;
    prop_assert!(
        audit.hmac_ok && audit.rows_verified > 0,
        "audit HMAC verification failed: {:?}",
        audit
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn live_authorization_and_grant_lifecycle_conform(trace in prop::collection::vec(steps(), 15..31)) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let start = [
            Step::Unlock(true), Step::Register(true),
            Step::Prepare(Scope::DEV, true, Credential::Fresh),
        ];
        runtime.block_on(run_trace(start.into_iter().chain(trace)))?;
    }
}
