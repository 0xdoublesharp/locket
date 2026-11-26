use super::{
    ApplyResult, CommitAuthorization, Result, identity, load_key, nanos, reject, store_key,
};
use ed25519_dalek::SigningKey;
use locket_core::team_package::{
    DeviceIdentity, SignedStatement, TeamBlob, TeamMember, TeamProfile, TeamSecret, TeamStatement,
    digest,
};
use locket_crypto::{
    EncryptedSecretValue, KeyBytes, KeyPurpose, KeyWrapAad, KeyWrapPurpose, SecretBlobAad,
    decrypt_secret_value_v1, key_wrap_aad_v1, secret_blob_aad_v1, secret_fingerprint_v1,
    unwrap_dek_v1, wrap_dek_v1,
};
use locket_store::{AuditWrite, DeviceRecord, Store, TeamRecord};
use rusqlite::{OptionalExtension, params};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn anchor(store: &Store, project: &str) -> Result<Option<(String, DeviceIdentity)>> {
    let row: Option<(String, String)> = store
        .connection()
        .query_row(
            "SELECT team_id,owner_json FROM team_sync_anchors WHERE project_id=?1",
            [project],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(team, json)| Ok((team, serde_json::from_str(&json)?))).transpose()
}
pub(super) fn local_owner(store: &Store, project: &str) -> Result<(String, DeviceIdentity)> {
    let (team, owner) =
        anchor(store, project)?.ok_or_else(|| reject("initialize and pin the owner first"))?;
    let local =
        store.get_active_local_device(project)?.ok_or_else(|| reject("local device missing"))?;
    if identity(&local)? != owner
        || store
            .get_active_team_member_by_device(&team, &local.id)?
            .is_none_or(|m| m.role != "owner")
    {
        return Err(reject("only the pinned protected owner can perform this operation"));
    }
    Ok((team, owner))
}
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn initialize_owner(
    store: &mut Store,
    project: &str,
    owner: &DeviceIdentity,
    now: i64,
) -> Result<()> {
    let team = store.get_team_by_project(project)?.ok_or_else(|| reject("run team init first"))?;
    let local =
        store.get_active_local_device(project)?.ok_or_else(|| reject("local device missing"))?;
    if identity(&local)? != *owner
        || store
            .get_active_team_member_by_device(&team.id, &local.id)?
            .is_none_or(|m| m.role != "owner")
    {
        return Err(reject("protected local owner required"));
    }
    if let Some((existing_team, existing)) = anchor(store, project)? {
        if existing != *owner || existing_team != team.id {
            return Err(reject("owner changed; explicit independent re-pin required"));
        }
        return Ok(());
    }
    store.connection().execute("INSERT INTO team_sync_anchors(project_id,team_id,owner_json,pinned_at) VALUES (?1,?2,?3,?4)",params![project,team.id,serde_json::to_string(owner)?,nanos(now)?])?;
    Ok(())
}
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn add_recipient(
    store: &mut Store,
    project: &str,
    recipient: &DeviceIdentity,
    name: &str,
    role: &str,
    profiles: &[String],
    now: i64,
) -> Result<()> {
    let (team, owner) = local_owner(store, project)?;
    if !recipient.valid()
        || *recipient == owner
        || name.trim().is_empty()
        || !["developer", "maintainer", "read-only"].contains(&role)
        || profiles.is_empty()
    {
        return Err(reject("invalid recipient or role"));
    }
    let all = store.list_profiles(project)?;
    let names: Vec<_> = profiles
        .iter()
        .map(|id| {
            all.iter()
                .find(|p| &p.id == id)
                .map(|p| p.name.clone())
                .ok_or_else(|| reject("profile outside project"))
        })
        .collect::<Result<_>>()?;
    if profiles.iter().collect::<BTreeSet<_>>().len() != profiles.len()
        || store.bundle_recipient_is_denied(project, &recipient.sealing_key)?
    {
        return Err(reject("recipient revoked or duplicate scope"));
    }
    store.with_atomic_write(|store| {
        let existing = store.find_device(project, &recipient.id)?;
        if existing.is_some_and(|d| identity(&d).ok().as_ref() != Some(recipient)) {
            return Err(reject("device identity collision"));
        }
        if store.find_device(project, &recipient.id)?.is_none() {
            store.insert_device(&device_row(project, recipient, name, false, now)?)?;
        }
        if store.get_team_member_by_device(&team, &recipient.id)?.is_some() {
            return Err(reject("recipient already has membership"));
        }
        let member_id = locket_core::MemberId::generate()
            .map_err(|_| reject("clock unavailable"))?
            .into_string();
        store.insert_team_member(
            &member_id,
            &team,
            Some(&recipient.id),
            name,
            role,
            nanos(now)?,
        )?;
        store.set_team_member_profiles(&member_id, &names)?;
        Ok(())
    })
}
fn device_row(
    project: &str,
    id: &DeviceIdentity,
    name: &str,
    local: bool,
    now: i64,
) -> Result<DeviceRecord> {
    Ok(DeviceRecord {
        id: id.id.clone(),
        project_id: project.into(),
        member_id: None,
        name: name.into(),
        label: name.into(),
        signing_public_key: id.signing_key.to_vec(),
        sealing_public_key: id.sealing_key.to_vec(),
        fingerprint: id.fingerprint.clone(),
        safety_words: vec![],
        local,
        created_at: nanos(now)?,
        last_seen_at: None,
        revoked_at: None,
    })
}
fn roster(store: &Store, project: &str, team: &str) -> Result<Vec<TeamMember>> {
    let profiles = store.list_profiles(project)?;
    let mut result = Vec::new();
    let mut stmt=store.connection().prepare("SELECT id,display_name,role,profiles_json,device_id,removed_at FROM team_members WHERE team_id=?1 ORDER BY id")?;
    let rows = stmt
        .query_map([team], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<i64>>(5)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (id, name, role, scope, device, removed) in rows {
        let Some(device) = device else {
            continue;
        };
        let Some(record) = store.find_device(project, &device)? else {
            continue;
        };
        let profile_ids = if role == "owner" {
            profiles.iter().map(|p| p.id.clone()).collect()
        } else {
            let names: Vec<String> = scope
                .map(|s| serde_json::from_str(&s))
                .transpose()?
                .ok_or_else(|| reject("member has unknown profile scope"))?;
            names
                .iter()
                .map(|name| {
                    profiles
                        .iter()
                        .find(|p| p.name == *name || p.id == *name)
                        .map(|p| p.id.clone())
                        .ok_or_else(|| reject("member profile missing"))
                })
                .collect::<Result<Vec<_>>>()?
        };
        result.push(TeamMember {
            id,
            name,
            role,
            profiles: profile_ids,
            device: identity(&record)?,
            removed: removed.is_some() || record.revoked_at.is_some(),
        });
    }
    Ok(result)
}
fn current_secret(
    store: &Store,
    project: &str,
    profile: &str,
    id: &str,
) -> Result<Option<TeamSecret>> {
    let record = store.list_secrets_by_profile(project, profile)?.into_iter().find(|s| s.id == id);
    record
        .map(|s| {
            let blob = if s.state == "active" {
                store.get_blob(&s.id, s.current_version)?.map(|b| TeamBlob {
                    encrypted_dek: b.encrypted_dek,
                    ciphertext: b.ciphertext,
                    value_nonce: b.value_nonce,
                    aad_schema_version: b.aad_schema_version,
                })
            } else {
                None
            };
            if s.source != "team-managed" {
                return Err(reject("shared secret collides with personal source"));
            }
            Ok(TeamSecret {
                id: s.id,
                name: s.name,
                version: s.current_version,
                deleted: s.state != "active",
                created_at: s.created_at,
                blob,
            })
        })
        .transpose()
}
fn value_aads(project: &str, profile: &str, secret: &TeamSecret) -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((
        secret_blob_aad_v1(&SecretBlobAad::new(
            project,
            profile,
            &secret.id,
            &secret.name,
            secret.version,
        ))?,
        key_wrap_aad_v1(&KeyWrapAad::new(
            project,
            &secret.id,
            Some(profile),
            secret.version,
            KeyWrapPurpose::SecretDek,
        ))?,
    ))
}
fn plaintext(
    project: &str,
    profile: &TeamProfile,
    secret: &TeamSecret,
) -> Result<Option<zeroize::Zeroizing<String>>> {
    let Some(blob) = &secret.blob else {
        return Ok(None);
    };
    if blob.aad_schema_version != 1 {
        return Err(reject("unsupported blob AAD"));
    }
    let (value, wrap) = value_aads(project, &profile.id, secret)?;
    Ok(Some(decrypt_secret_value_v1(
        &profile.secret_key,
        &EncryptedSecretValue {
            encrypted_dek: blob.encrypted_dek.clone(),
            ciphertext: blob.ciphertext.clone(),
            value_nonce: blob.value_nonce,
            aad_schema_version: blob.aad_schema_version,
        },
        &value,
        &wrap,
    )?))
}
fn profile_snapshot(
    store: &Store,
    project: &str,
    id: &str,
    master: &KeyBytes,
) -> Result<TeamProfile> {
    let profile = store
        .list_profiles(project)?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| reject("profile missing"))?;
    let epoch = store
        .connection()
        .query_row(
            "SELECT epoch FROM team_sync_profile_epochs WHERE project_id=?1 AND profile_id=?2",
            (project, id),
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(1);
    let mut snapshot = TeamProfile {
        id: profile.id,
        name: profile.name,
        dangerous: profile.dangerous,
        created_at: profile.created_at,
        key_epoch: epoch,
        secret_key: *load_key(store, project, Some(id), KeyPurpose::ProfileSecret, master)?,
        fingerprint_key: *load_key(
            store,
            project,
            Some(id),
            KeyPurpose::ProfileFingerprint,
            master,
        )?,
        secrets: vec![],
    };
    for secret in store.list_secrets_by_profile(project, id)? {
        if secret.source == "team-managed" {
            let row = current_secret(store, project, id, &secret.id)?
                .ok_or_else(|| reject("missing secret"))?;
            plaintext(project, &snapshot, &row)?;
            snapshot.secrets.push(row);
        }
    }
    snapshot.secrets.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(snapshot)
}
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn publish(
    store: &mut Store,
    project: &str,
    master: &KeyBytes,
    signer: &SigningKey,
    now: i64,
) -> Result<usize> {
    publish_guarded(store, project, master, signer, now, None)
}
/// Publishes after optional unlock-context reauthorization at commit.
/// # Errors
/// Rejects unauthorized publishers, changed predecessors and invalid storage or crypto.
pub fn publish_guarded(
    store: &mut Store,
    project: &str,
    master: &KeyBytes,
    signer: &SigningKey,
    now: i64,
    authorization: Option<&CommitAuthorization>,
) -> Result<usize> {
    Ok(publish_with_warnings(store, project, master, signer, now, authorization)?.queued)
}

/// Local publication result. Warnings are separate from the signed statement.
#[derive(Debug)]
pub struct PublicationResult {
    pub queued: usize,
    pub warnings: Vec<String>,
}

/// Publishes and reports which Global Vault links stay on the publishing machine.
///
/// # Errors
/// Rejects unauthorized publishers, changed predecessors and invalid storage or crypto.
pub fn publish_with_warnings(
    store: &mut Store,
    project: &str,
    master: &KeyBytes,
    signer: &SigningKey,
    now: i64,
    authorization: Option<&CommitAuthorization>,
) -> Result<PublicationResult> {
    let (team, owner) = local_owner(store, project)?;
    if signer.verifying_key().to_bytes() != owner.signing_key {
        return Err(reject("protected signing key does not match owner pin"));
    }
    let members = roster(store, project, &team)?;
    let ids: BTreeSet<_> =
        members.iter().filter(|m| !m.removed).flat_map(|m| m.profiles.iter()).collect();
    let profiles = ids
        .into_iter()
        .map(|id| profile_snapshot(store, project, id, master))
        .collect::<Result<Vec<_>>>()?;
    let keys: BTreeMap<_, _> =
        profiles.iter().map(|p| (p.id.clone(), digest(&p.secret_key))).collect();
    let prior: Option<(String, String)> = store
        .connection()
        .query_row(
            "SELECT members_json,keys_json FROM team_sync_publications WHERE project_id=?1",
            [project],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((roster_json, key_json)) = &prior {
        let old: Vec<TeamMember> = serde_json::from_str(roster_json)?;
        let old_keys: BTreeMap<String, String> = serde_json::from_str(key_json)?;
        for member in old.iter().filter(|m| !m.removed) {
            let next = members
                .iter()
                .find(|m| m.device.fingerprint == member.device.fingerprint && !m.removed);
            for profile in &member.profiles {
                if next.is_none_or(|m| !m.profiles.contains(profile))
                    && (!keys.contains_key(profile) || old_keys.get(profile) == keys.get(profile))
                {
                    return Err(reject(
                        "publishing blocked: removed recipient requires rotation of affected profile encryption keys and provider credentials",
                    ));
                }
            }
        }
    }
    let mut packages = Vec::new();
    for member in members.iter().filter(|m| !m.removed && m.device != owner) {
        let old:Option<(i64,String,String,i64)>=store.connection().query_row("SELECT epoch,digest,content_digest,expires_at FROM team_sync_outbound WHERE project_id=?1 AND recipient=?2",(project,&member.device.fingerprint),|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let mut statement = TeamStatement {
            v: 1,
            team_id: team.clone(),
            project_id: project.into(),
            epoch: 0,
            previous_digest: String::new(),
            issued_at: 0,
            expires_at: 0,
            nonce: [0; 24],
            publisher: owner.clone(),
            recipient: member.device.clone(),
            members: members.clone(),
            profiles: profiles
                .iter()
                .filter(|p| member.profiles.contains(&p.id))
                .cloned()
                .collect(),
        };
        let content_bytes = zeroize::Zeroizing::new(serde_json::to_vec(&statement)?);
        let content_digest = digest(&content_bytes);
        if old.as_ref().is_some_and(|o| o.2 == content_digest && o.3 > now.saturating_add(86400)) {
            continue;
        }
        statement.epoch = u64::try_from(
            old.as_ref()
                .map_or(Ok(1), |o| o.0.checked_add(1).ok_or_else(|| reject("epoch overflow")))?,
        )
        .map_err(|_| reject("invalid epoch"))?;
        let expected_head = old.as_ref().map(|row| (row.0, row.1.clone()));
        statement.previous_digest = old.map_or_else(String::new, |o| o.1);
        statement.issued_at = now;
        statement.expires_at =
            now.checked_add(7 * 86400).ok_or_else(|| reject("timestamp overflow"))?;
        statement.nonce = locket_crypto::random_bytes()?;
        let envelope = SignedStatement::sign(&statement, signer)?;
        envelope.verify(&owner.fingerprint, project, &member.device, now)?;
        let statement_digest = digest(&envelope.statement);
        let bytes = envelope.seal(&member.device.sealing_key)?;
        let prefix = super::transport::recipient_prefix(&member.device.fingerprint)?;
        let filename = format!("{prefix}{:08}-{}.lkpkg", statement.epoch, &digest(&bytes)[..16]);
        packages.push((
            member.device.fingerprint.clone(),
            statement.epoch,
            statement.expires_at,
            statement_digest,
            content_digest,
            filename,
            bytes,
            expected_head,
        ));
    }
    let _authorization = authorization.map(|authorize| authorize()).transpose()?;
    store.with_atomic_write(|store| {
        let (current_team, current_owner) = local_owner(store, project)?;
        if current_team != team || current_owner != owner {
            return Err(reject("publisher owner changed; retry publication"));
        }
        if roster(store,project,&team)? != members {
            return Err(reject("membership changed while preparing publication; retry"));
        }
        for profile in &profiles {
            if profile_snapshot(store,project,&profile.id,master)? != *profile {
                return Err(reject("profile content changed while preparing publication; retry"));
            }
        }
        for (recipient,_,_,_,_,_,_,expected_head) in &packages {
            let current_head: Option<(i64,String)> = store.connection().query_row("SELECT epoch,digest FROM team_sync_outbound WHERE project_id=?1 AND recipient=?2", (project,recipient), |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
            if &current_head != expected_head {
                return Err(reject("publisher predecessor changed; retry publication"));
            }
        }
        for (recipient,epoch,expiry,hash,content,filename,bytes,_) in &packages {
            store.connection().execute("INSERT INTO team_sync_outbound VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(project_id,recipient) DO UPDATE SET epoch=excluded.epoch,digest=excluded.digest,content_digest=excluded.content_digest,expires_at=excluded.expires_at",params![project,recipient,i64::try_from(*epoch).map_err(|_|reject("epoch overflow"))?,hash,content,expiry])?;
            store.connection().execute("INSERT INTO team_sync_outbox(project_id,filename,recipient,ciphertext) VALUES (?1,?2,?3,?4)",params![project,filename,recipient,bytes])?;
        }
        store.connection().execute("INSERT INTO team_sync_publications VALUES (?1,?2,?3) ON CONFLICT(project_id) DO UPDATE SET members_json=excluded.members_json,keys_json=excluded.keys_json",params![project,serde_json::to_string(&members)?,serde_json::to_string(&keys)?])?;
        if !packages.is_empty() {audit_event(store,project,master,"TEAM_SYNC_PUBLISH",now,&serde_json::json!({"package_count":packages.len()}))?;}
        let mut warnings = Vec::new();
        for profile in &profiles {
            if !members.iter().any(|member| {
                !member.removed && member.device != owner && member.profiles.contains(&profile.id)
            }) {
                continue;
            }
            let names = store
                .list_active_secret_links_by_profile(project, &profile.id)?
                .into_iter()
                .map(|resolved| resolved.link.local_name)
                .collect::<Vec<_>>();
            if !names.is_empty() {
                warnings.push(format!(
                    "Global Vault links in profile {} stay on this machine: {}. Teammates and CI need team-managed or local values for these variables.",
                    profile.name,
                    names.join(", "),
                ));
            }
        }
        Ok(PublicationResult { queued: packages.len(), warnings })
    })
}

/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn apply_package(
    store: &mut Store,
    bytes: &[u8],
    master: &KeyBytes,
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    project: &str,
    owner_pin: Option<&str>,
    now: i64,
) -> Result<ApplyResult> {
    apply_package_guarded(store, bytes, master, sealing, local, project, owner_pin, now, None)
}
/// Applies a verified snapshot after optional unlock-context reauthorization at commit.
/// # Errors
/// Rejects unauthenticated state, revoked scope, changed history or invalid local data.
pub fn apply_package_guarded(
    store: &mut Store,
    bytes: &[u8],
    master: &KeyBytes,
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    project: &str,
    owner_pin: Option<&str>,
    now: i64,
    authorization: Option<&CommitAuthorization>,
) -> Result<ApplyResult> {
    apply_package_with_consent_guarded(
        store,
        bytes,
        master,
        sealing,
        local,
        project,
        owner_pin,
        now,
        true,
        authorization,
    )
}
/// Advances security state while unapproved values remain encrypted.
/// # Errors
/// Rejects invalid authentication, history, local key scope or commit authorization.
pub fn apply_package_with_consent_guarded(
    store: &mut Store,
    bytes: &[u8],
    master: &KeyBytes,
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    project: &str,
    owner_pin: Option<&str>,
    now: i64,
    allow_dangerous: bool,
    authorization: Option<&CommitAuthorization>,
) -> Result<ApplyResult> {
    let local_record = store
        .get_active_local_device(project)?
        .ok_or_else(|| reject("prepare a local device before joining"))?;
    if identity(&local_record)? != *local {
        return Err(reject("recipient differs from local device"));
    }
    let existing = anchor(store, project)?;
    let pin = existing
        .as_ref()
        .map(|(_, o)| o.fingerprint.as_str())
        .or(owner_pin)
        .ok_or_else(|| reject("independent full owner fingerprint required for first trust"))?;
    if owner_pin.is_some_and(|p| p != pin) {
        return Err(reject("owner pin changed; explicit re-pin required"));
    }
    let signed = SignedStatement::open(bytes, sealing)?;
    let head: Option<(i64, String, String, String)> = store
        .connection()
        .query_row(
            "SELECT epoch,digest,state,members_json FROM team_sync_heads WHERE project_id=?1",
            [project],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let verified = if head.is_some() {
        signed.verify_update(pin, project, local, now)?
    } else {
        signed.verify(pin, project, local, now)?
    };
    let statement = &verified.statement;
    let incoming_epoch = i64::try_from(statement.epoch).map_err(|_| reject("epoch overflow"))?;
    if existing
        .as_ref()
        .is_some_and(|(team, owner)| team != &statement.team_id || owner != &statement.publisher)
    {
        return Err(reject("team or pinned signing identity changed"));
    }
    if let Some((epoch, hash, state, _)) = &head {
        let join_epoch: Option<i64> = store
            .connection()
            .query_row(
                "SELECT epoch FROM team_sync_join_checkpoints WHERE project_id=?1",
                [project],
                |row| row.get(0),
            )
            .optional()?;
        if join_epoch.is_some_and(|first| incoming_epoch < first) {
            let _authorization = authorization.map(|authorize| authorize()).transpose()?;
            store.connection().execute(
                "INSERT OR IGNORE INTO team_sync_seen VALUES (?1,?2,?3,'pre_anchor')",
                params![project, verified.digest, incoming_epoch],
            )?;
            return Ok(ApplyResult { duplicate: true, ..ApplyResult::default() });
        }
        if *epoch == incoming_epoch && *hash == verified.digest {
            return Ok(ApplyResult { duplicate: true, ..ApplyResult::default() });
        }
        if state == "fork" {
            return Err(reject(
                "sync stopped after fork; obtain explicit owner recovery checkpoint",
            ));
        }
        let seen:bool=store.connection().query_row("SELECT EXISTS(SELECT 1 FROM team_sync_seen WHERE project_id=?1 AND digest=?2 AND outcome='applied')",(project,&verified.digest),|r|r.get(0))?;
        if seen {
            return Ok(ApplyResult { duplicate: true, ..ApplyResult::default() });
        }
        if incoming_epoch <= *epoch
            || (incoming_epoch == epoch + 1 && statement.previous_digest != *hash)
        {
            let _authorization = authorization.map(|authorize| authorize()).transpose()?;
            let marked = store.connection().execute(
                "UPDATE team_sync_heads SET state='fork'
                 WHERE project_id=?1 AND epoch=?2 AND digest=?3",
                params![project, epoch, hash],
            )?;
            if marked == 0 {
                return Err(reject("receiver predecessor changed; retry"));
            }
            return Err(reject("fork or rollback detected; automatic sync stopped"));
        }
        if incoming_epoch != epoch + 1 {
            return Err(super::SyncError::MissingPredecessor);
        }
    }
    // Authenticate every active value before a transaction can advance security state.
    for profile in &statement.profiles {
        for secret in &profile.secrets {
            plaintext(project, profile, secret)?;
        }
    }
    let _authorization = authorization.map(|authorize| authorize()).transpose()?;
    store.with_atomic_write(|store| {
        let current_head: Option<(i64, String, String)> = store.connection().query_row(
            "SELECT epoch,digest,state FROM team_sync_heads WHERE project_id=?1",
            [project], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        ).optional()?;
        if current_head.as_ref().is_some_and(|row| row.2 == "fork") {
            return Err(reject("sync stopped after fork; obtain explicit owner recovery checkpoint"));
        }
        if current_head != head.as_ref().map(|row| (row.0, row.1.clone(), row.2.clone()))
            || anchor(store, project)? != existing
        {
            return Err(reject("receiver predecessor changed; retry"));
        }
        let previous = head.as_ref().map(|row| row.3.as_str());
        validate_roster_transition(store, statement, previous)?;
        if existing.is_none() {
            if store.get_team_by_project(project)?.is_some_and(|t|t.id!=statement.team_id) {return Err(reject("existing team differs; use a separate store"));}
            if store.get_team_by_project(project)?.is_none() {store.insert_team(&TeamRecord{id:statement.team_id.clone(),project_id:project.into(),name:statement.team_id.clone(),created_at:nanos(now)?,updated_at:nanos(now)?})?;}
            store.connection().execute("INSERT INTO team_sync_anchors VALUES (?1,?2,?3,?4)",params![project,statement.team_id,serde_json::to_string(&statement.publisher)?,nanos(now)?])?;
        }
        if head.is_none() {
            store.connection().execute("INSERT INTO team_sync_join_checkpoints VALUES (?1,?2)",params![project,incoming_epoch])?;
        }
        apply_roster(store,statement,now)?;
        let mut result=ApplyResult { removed:statement.members.iter().find(|m|m.device==*local).is_none_or(|m|m.removed), ..ApplyResult::default() };
        // Store ciphertext once per project, not once per pending profile.
        store.connection().execute("DELETE FROM team_sync_pending_packages WHERE project_id=?1",[project])?;
        store.connection().execute("INSERT INTO team_sync_pending_packages VALUES (?1,?2,?3,?4)",params![project,incoming_epoch,verified.digest,bytes])?;
        for profile in &statement.profiles {
            apply_profile_or_hold(store,statement,profile,master,bytes,&mut result,head.is_some(),now,allow_dangerous)?;
        }
        if result.pending_profiles==0 {store.connection().execute("DELETE FROM team_sync_pending_packages WHERE project_id=?1",[project])?;}
        store.connection().execute("INSERT INTO team_sync_heads VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(project_id) DO UPDATE SET epoch=excluded.epoch,digest=excluded.digest,members_json=excluded.members_json,state=excluded.state,verified_at=excluded.verified_at",params![project,incoming_epoch,verified.digest,serde_json::to_string(&statement.members)?,if result.removed {"removed"}else if result.pending_profiles>0 {"pending-values"}else{"verified"},nanos(now)?])?;
        store.connection().execute("INSERT INTO team_sync_seen VALUES (?1,?2,?3,'applied')",params![project,verified.digest,incoming_epoch])?;
        if store.get_key_by_scope(project,None,KeyPurpose::Audit.as_str())?.is_some() {
            let key=load_key(store,project,None,KeyPurpose::Audit,master)?;
            store.append_audit(key.as_ref(),&AuditWrite{project_id:project,profile_id:None,action:"TEAM_SYNC",status:"SUCCESS",secret_name:None,command:Some("team sync"),metadata_json:&serde_json::json!({"schema_version":2,"action":"TEAM_SYNC","status":"SUCCESS","command":"team sync","project_id":project,"epoch":statement.epoch,"applied":result.applied,"conflicts":result.conflicts,"pending_profiles":result.pending_profiles}),timestamp:nanos(now)?})?;
        }
        Ok(result)
    })
}
fn validate_roster_transition(
    store: &Store,
    statement: &TeamStatement,
    previous_roster: Option<&str>,
) -> Result<()> {
    let previous: Vec<TeamMember> =
        previous_roster.map(serde_json::from_str).transpose()?.unwrap_or_default();
    for member in &statement.members {
        let binding: Option<(String, Option<String>)> = store
            .connection()
            .query_row(
                "SELECT team_id,device_id FROM team_members WHERE id=?1",
                [&member.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((team, device)) = binding {
            if team != statement.team_id {
                return Err(reject("cross-team member ID"));
            }
            if device.as_deref() != Some(member.device.id.as_str()) {
                return Err(reject("member ID cannot change device identity"));
            }
        }
        if member.removed {
            continue;
        }
        if previous
            .iter()
            .any(|old| old.removed && old.device.sealing_key == member.device.sealing_key)
        {
            return Err(reject("revoked identity cannot be reinstated"));
        }
        // Omission leaves a local tombstone. The sealing key identifies recipients
        // even when a later statement uses a new device or member ID.
        if store.bundle_recipient_is_denied(&statement.project_id, &member.device.sealing_key)? {
            return Err(reject("removed membership cannot be reinstated"));
        }
    }
    Ok(())
}

fn apply_roster(store: &Store, s: &TeamStatement, now: i64) -> Result<()> {
    // Retain absent members as revoked. A snapshot cannot erase revocation history.
    store.connection().execute(
        "UPDATE team_members SET removed_at=MAX(joined_at,?2)
         WHERE team_id=?1 AND removed_at IS NULL",
        params![s.team_id, nanos(now)?],
    )?;
    for m in &s.members {
        if let Some(device) = store.find_device(&s.project_id, &m.device.id)? {
            if identity(&device)? != m.device {
                return Err(reject("device ID identity collision"));
            }
        } else {
            let other: bool = store.connection().query_row(
                "SELECT EXISTS(SELECT 1 FROM devices WHERE id=?1)",
                [&m.device.id],
                |r| r.get(0),
            )?;
            if other {
                return Err(reject("cross-project device ID"));
            }
            store.insert_device(&device_row(
                &s.project_id,
                &m.device,
                &m.device.id,
                false,
                now,
            )?)?;
        }
        store.connection().execute(
            "INSERT INTO team_members(id,team_id,device_id,display_name,role,profiles_json,joined_at,removed_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(id) DO UPDATE SET role=excluded.role,profiles_json=excluded.profiles_json,
                 removed_at=CASE WHEN excluded.removed_at IS NULL THEN NULL ELSE team_members.removed_at END",
            params![m.id,s.team_id,m.device.id,m.name,m.role,serde_json::to_string(&m.profiles)?,
                nanos(now)?,if m.removed {Some(nanos(now)?)} else {None}],
        )?;
        if m.removed {
            store.connection().execute(
                "UPDATE devices SET revoked_at=COALESCE(revoked_at,?2) WHERE id=?1",
                params![m.device.id, nanos(now)?],
            )?;
        }
    }
    Ok(())
}
fn apply_profile(
    store: &Store,
    s: &TeamStatement,
    p: &TeamProfile,
    master: &KeyBytes,
    package: &[u8],
    result: &mut ApplyResult,
    has_head: bool,
    now: i64,
    apply_values: bool,
) -> Result<()> {
    let project = &s.project_id;
    let owner: Option<String> = store
        .connection()
        .query_row("SELECT project_id FROM profiles WHERE id=?1", [&p.id], |r| r.get(0))
        .optional()?;
    if owner.as_ref().is_some_and(|o| o != project) {
        return Err(reject("cross-project profile ID"));
    }
    if let Some(collision) = store.get_profile_by_name(project, &p.name)?
        && collision.id != p.id
        && locket_store::archive_empty_profile_for_import(
            store.connection(),
            project,
            &collision.id,
        )?
        .is_none()
    {
        return Err(reject("populated profile name collision; use a separate store"));
    }
    store.insert_profile_if_absent(&p.id, project, &p.name, p.dangerous, p.created_at)?;
    store.connection().execute(
        "UPDATE profiles SET dangerous=MAX(dangerous,?2) WHERE id=?1",
        params![p.id, p.dangerous],
    )?;
    let prior_epoch: Option<u32> = store
        .connection()
        .query_row(
            "SELECT epoch FROM team_sync_profile_epochs WHERE project_id=?1 AND profile_id=?2",
            (project, &p.id),
            |r| r.get(0),
        )
        .optional()?;
    if prior_epoch.is_some_and(|e| e > p.key_epoch) {
        return Err(reject("profile key epoch rollback"));
    }
    let mut conflicts = BTreeSet::new();
    for secret in store
        .list_secrets_by_profile(project, &p.id)?
        .into_iter()
        .filter(|s| s.source == "team-managed")
    {
        let local = current_secret(store, project, &p.id, &secret.id)?
            .ok_or_else(|| reject("secret missing"))?;
        let baseline: Option<String> = store
            .connection()
            .query_row(
                "SELECT digest FROM team_sync_values WHERE project_id=?1 AND secret_id=?2",
                (project, &secret.id),
                |r| r.get(0),
            )
            .optional()?;
        if baseline
            .as_ref()
            .is_none_or(|b| *b != digest(&serde_json::to_vec(&local).unwrap_or_default()))
        {
            conflicts.insert(secret.id);
        }
    }
    let old_key = if store
        .get_key_by_scope(project, Some(&p.id), KeyPurpose::ProfileSecret.as_str())?
        .is_some()
    {
        Some(load_key(store, project, Some(&p.id), KeyPurpose::ProfileSecret, master)?)
    } else {
        None
    };
    if let Some(old) = &old_key
        && **old != p.secret_key
    {
        if !has_head && !store.list_secrets_by_profile(project, &p.id)?.is_empty() {
            return Err(reject("bootstrap key collision with local values"));
        }
        if prior_epoch.is_some_and(|e| e >= p.key_epoch) {
            return Err(reject("key changed without newer epoch"));
        }
        rekey_profile(store, project, p, old)?;
        // Rewrapping changes blob bytes; refresh only rows proven unchanged first.
        for row in store
            .list_secrets_by_profile(project, &p.id)?
            .into_iter()
            .filter(|row| row.source == "team-managed" && !conflicts.contains(&row.id))
        {
            let updated = current_secret(store, project, &p.id, &row.id)?
                .ok_or_else(|| reject("rekeyed value missing"))?;
            store.connection().execute(
                "UPDATE team_sync_values SET digest=?3 WHERE project_id=?1 AND secret_id=?2",
                params![project, row.id, digest(&serde_json::to_vec(&updated)?)],
            )?;
        }
    }
    store_key(store, project, Some(&p.id), KeyPurpose::ProfileSecret, master, &p.secret_key, now)?;
    store_key(
        store,
        project,
        Some(&p.id),
        KeyPurpose::ProfileFingerprint,
        master,
        &p.fingerprint_key,
        now,
    )?;
    store.connection().execute("INSERT INTO team_sync_profile_epochs VALUES (?1,?2,?3) ON CONFLICT(project_id,profile_id) DO UPDATE SET epoch=excluded.epoch",params![project,p.id,p.key_epoch])?;
    if !apply_values {
        return Ok(());
    }
    for secret in &p.secrets {
        if conflicts.contains(&secret.id) {
            store.connection().execute("INSERT INTO team_sync_conflicts VALUES (?1,?2,?3,?4) ON CONFLICT(project_id,secret_id) DO UPDATE SET epoch=excluded.epoch,encrypted_package=excluded.encrypted_package",params![project,secret.id,i64::try_from(s.epoch).map_err(|_| reject("epoch overflow"))?,package])?;
            result.conflicts += 1;
            continue;
        }
        apply_secret(store, project, p, secret, now, false)?;
        result.applied += 1;
    }
    // Complete scope: deletions may affect only previously synchronized shared rows.
    for local in store
        .list_secrets_by_profile(project, &p.id)?
        .into_iter()
        .filter(|r| r.source == "team-managed")
    {
        if !p.secrets.iter().any(|r| r.id == local.id) {
            if conflicts.contains(&local.id) {
                store.connection().execute("INSERT INTO team_sync_conflicts VALUES (?1,?2,?3,?4) ON CONFLICT(project_id,secret_id) DO UPDATE SET epoch=excluded.epoch,encrypted_package=excluded.encrypted_package",params![project,local.id,i64::try_from(s.epoch).map_err(|_| reject("epoch overflow"))?,package])?;
                result.conflicts += 1;
            } else {
                store.connection().execute(
                    "UPDATE secrets SET state='deleted',deleted_at=?2 WHERE id=?1",
                    params![local.id, nanos(now)?],
                )?;
                let deleted = current_secret(store, project, &p.id, &local.id)?
                    .ok_or_else(|| reject("deleted row missing"))?;
                store.connection().execute(
                    "UPDATE team_sync_values SET digest=?3 WHERE project_id=?1 AND secret_id=?2",
                    params![project, local.id, digest(&serde_json::to_vec(&deleted)?)],
                )?;
            }
        }
    }
    Ok(())
}
fn rekey_profile(store: &Store, project: &str, p: &TeamProfile, old: &KeyBytes) -> Result<()> {
    for secret in store.list_secrets_by_profile(project, &p.id)? {
        for version in store.list_secret_versions(&secret.id)? {
            if let Some(blob) = store.get_blob(&secret.id, version.version)? {
                let aad = key_wrap_aad_v1(&KeyWrapAad::new(
                    project,
                    &secret.id,
                    Some(&p.id),
                    version.version,
                    KeyWrapPurpose::SecretDek,
                ))?;
                let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
                    project,
                    &p.id,
                    &secret.id,
                    &secret.name,
                    version.version,
                ))?;
                let value = decrypt_secret_value_v1(
                    old,
                    &EncryptedSecretValue {
                        encrypted_dek: blob.encrypted_dek.clone(),
                        ciphertext: blob.ciphertext.clone(),
                        value_nonce: blob.value_nonce,
                        aad_schema_version: blob.aad_schema_version,
                    },
                    &value_aad,
                    &aad,
                )?;
                let fp = secret_fingerprint_v1(&p.fingerprint_key, &value)?;
                store.connection().execute(
                    "UPDATE fingerprints SET fingerprint=?3 WHERE secret_id=?1 AND version=?2",
                    params![secret.id, version.version, fp.as_slice()],
                )?;
                let dek = unwrap_dek_v1(old, &blob.encrypted_dek, &aad)?;
                let wrapped = wrap_dek_v1(&p.secret_key, &dek, &aad)?;
                store.connection().execute(
                    "UPDATE blobs SET encrypted_dek=?3 WHERE secret_id=?1 AND version=?2",
                    params![secret.id, version.version, wrapped],
                )?;
            }
        }
    }
    Ok(())
}
fn apply_secret(
    store: &Store,
    project: &str,
    p: &TeamProfile,
    s: &TeamSecret,
    now: i64,
    force: bool,
) -> Result<()> {
    let existing: Option<(String, String, String, u32, String)> = store
        .connection()
        .query_row(
            "SELECT project_id,profile_id,source,current_version,name FROM secrets WHERE id=?1",
            [&s.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    if existing.as_ref().is_some_and(|r| {
        r.0 != project || r.1 != p.id || r.2 != "team-managed" || (!force && r.3 > s.version)
    }) {
        return Err(reject("secret scope/version collision"));
    }
    // Historical blobs authenticate the stored name as well as the ID and version.
    if existing.is_some_and(|row| row.4 != s.name) {
        return Err(reject("secret name changed for an existing secret ID"));
    }
    if !force
        && let Some(local) = current_secret(store, project, &p.id, &s.id)?
        && local.version == s.version
        && local != *s
        && (local.deleted || !s.deleted)
    {
        let same_value = local.name == s.name
            && local.deleted == s.deleted
            && plaintext(project, p, &local)? == plaintext(project, p, s)?;
        if !same_value {
            return Err(reject("different contents at the same secret version"));
        }
    }
    let collision = store.get_secret_by_source(project, &p.id, &s.name, "team-managed")?;
    if collision.is_some_and(|r| r.id != s.id) {
        return Err(reject("shared secret name collision"));
    }
    store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at,deleted_at) VALUES (?1,?2,?3,?4,'team-managed','team-accept',0,?5,?6,?7,?8,?9) ON CONFLICT(id) DO UPDATE SET current_version=excluded.current_version,state=excluded.state,updated_at=excluded.updated_at,deleted_at=excluded.deleted_at",params![s.id,project,p.id,s.name,s.version,if s.deleted{"deleted"}else{"active"},s.created_at,nanos(now)?,if s.deleted{Some(nanos(now)?)}else{None}])?;
    store.connection().execute("UPDATE secret_versions SET state='deprecated' WHERE secret_id=?1 AND version!=?2 AND state='current'",params![s.id,s.version])?;
    store.connection().execute("INSERT INTO secret_versions(secret_id,version,source,origin,state,created_at) VALUES (?1,?2,'team-managed','team-accept','current',?3) ON CONFLICT(secret_id,version) DO NOTHING",params![s.id,s.version,s.created_at])?;
    if let Some(blob) = &s.blob {
        store.connection().execute("INSERT INTO blobs VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(secret_id,version) DO UPDATE SET encrypted_dek=excluded.encrypted_dek,ciphertext=excluded.ciphertext,value_nonce=excluded.value_nonce",params![s.id,s.version,blob.encrypted_dek,blob.ciphertext,blob.value_nonce.as_slice(),blob.aad_schema_version,s.created_at])?;
        let value = plaintext(project, p, s)?.ok_or_else(|| reject("active blob missing"))?;
        let fp = secret_fingerprint_v1(&p.fingerprint_key, &value)?;
        store.connection().execute("INSERT INTO fingerprints VALUES (?1,?2,?3,?4) ON CONFLICT(secret_id,version) DO UPDATE SET fingerprint=excluded.fingerprint",params![s.id,s.version,fp.as_slice(),nanos(now)?])?;
    }
    store.connection().execute("INSERT INTO team_sync_values VALUES (?1,?2,?3) ON CONFLICT(project_id,secret_id) DO UPDATE SET digest=excluded.digest",params![project,s.id,digest(&serde_json::to_vec(s)?)])?;
    store.connection().execute(
        "DELETE FROM team_sync_conflicts WHERE project_id=?1 AND secret_id=?2",
        (project, &s.id),
    )?;
    Ok(())
}
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn resolve_conflict(
    store: &mut Store,
    project: &str,
    selector: &str,
    keep_local: bool,
    master: &KeyBytes,
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    now: i64,
) -> Result<()> {
    store.with_atomic_write(|store| {
        resolve_conflict_in_transaction(
            store, project, selector, keep_local, master, sealing, local, now,
        )
    })
}

fn resolve_conflict_in_transaction(
    store: &Store,
    project: &str,
    selector: &str,
    keep_local: bool,
    master: &KeyBytes,
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    now: i64,
) -> Result<()> {
    let (_, owner) = anchor(store, project)?.ok_or_else(|| reject("owner pin missing"))?;
    let mut stmt=store.connection().prepare("SELECT c.secret_id,c.encrypted_package FROM team_sync_conflicts c JOIN secrets s ON s.id=c.secret_id WHERE c.project_id=?1 AND (s.id=?2 OR s.name=?2)")?;
    let rows = stmt
        .query_map((project, selector), |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(stmt);
    if rows.len() != 1 {
        return Err(reject("select an unambiguous conflict by secret ID"));
    }
    let (id, bytes) = &rows[0];
    let signed = SignedStatement::open(bytes, sealing)?;
    let verified = signed.verify_update(&owner.fingerprint, project, local, now)?;
    let seen:bool=store.connection().query_row("SELECT EXISTS(SELECT 1 FROM team_sync_seen WHERE project_id=?1 AND digest=?2 AND outcome='applied')",(project,&verified.digest),|r|r.get(0))?;
    if !seen {
        return Err(reject("conflict package lacks an applied security checkpoint"));
    }
    let profile_id: String =
        store
            .connection()
            .query_row("SELECT profile_id FROM secrets WHERE id=?1", [id], |r| r.get(0))?;
    let profile = verified
        .statement
        .profiles
        .iter()
        .find(|p| p.id == profile_id)
        .ok_or_else(|| reject("conflict profile no longer granted"))?;
    let pending:bool=store.connection().query_row("SELECT EXISTS(SELECT 1 FROM team_sync_pending_profiles WHERE project_id=?1 AND profile_id=?2)",(project,&profile.id),|row|row.get(0))?;
    if pending {
        return Err(reject("profile has pending values; reconcile its profile conflict first"));
    }
    let current_members: String = store.connection().query_row(
        "SELECT members_json FROM team_sync_heads WHERE project_id=?1",
        [project],
        |row| row.get(0),
    )?;
    let current_members: Vec<TeamMember> = serde_json::from_str(&current_members)?;
    if !current_members.iter().any(|member| {
        member.device == *local && !member.removed && member.profiles.contains(&profile.id)
    }) {
        return Err(reject("current membership no longer grants this conflict profile"));
    }
    let current = current_secret(store, project, &profile.id, id)?
        .ok_or_else(|| reject("conflict value missing"))?;
    let current_key =
        load_key(store, project, Some(&profile.id), KeyPurpose::ProfileSecret, master)?;
    if *current_key != profile.secret_key {
        return Err(reject("conflict key epoch superseded; fetch latest owner snapshot"));
    }
    if keep_local && !current.deleted {
        if store.get_secret_by_source(project, &profile.id, &current.name, "user-local")?.is_some()
        {
            return Err(reject(
                "existing user-local override preserved; rename it before keeping this edit",
            ));
        }
        let value =
            plaintext(project, profile, &current)?.ok_or_else(|| reject("local value missing"))?;
        let local_id = locket_core::SecretId::generate()
            .map_err(|_| reject("clock unavailable"))?
            .into_string();
        let aad = secret_blob_aad_v1(&SecretBlobAad::new(
            project,
            &profile.id,
            &local_id,
            &current.name,
            1,
        ))?;
        let wrap = key_wrap_aad_v1(&KeyWrapAad::new(
            project,
            &local_id,
            Some(&profile.id),
            1,
            KeyWrapPurpose::SecretDek,
        ))?;
        let blob = locket_crypto::encrypt_secret_value_v1(&current_key, &value, &aad, &wrap)?;
        store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at) VALUES (?1,?2,?3,?4,'user-local','manual',0,1,'active',?5,?5)",params![local_id,project,profile.id,current.name,nanos(now)?])?;
        store.connection().execute("INSERT INTO secret_versions(secret_id,version,source,origin,state,created_at) VALUES (?1,1,'user-local','manual','current',?2)",params![local_id,nanos(now)?])?;
        store.connection().execute(
            "INSERT INTO blobs VALUES (?1,1,?2,?3,?4,1,?5)",
            params![
                local_id,
                blob.encrypted_dek,
                blob.ciphertext,
                blob.value_nonce.as_slice(),
                nanos(now)?
            ],
        )?;
        let fp = secret_fingerprint_v1(&profile.fingerprint_key, &value)?;
        store.connection().execute(
            "INSERT INTO fingerprints VALUES (?1,1,?2,?3)",
            params![local_id, fp.as_slice(), nanos(now)?],
        )?;
    }
    if let Some(incoming) = profile.secrets.iter().find(|s| &s.id == id) {
        store.connection().execute(
            "DELETE FROM secret_versions WHERE secret_id=?1 AND version>=?2",
            params![id, incoming.version],
        )?;
        apply_secret(store, project, profile, incoming, now, true)?;
    } else {
        store.connection().execute(
            "UPDATE secrets SET state='deleted',deleted_at=?2 WHERE id=?1",
            params![id, nanos(now)?],
        )?;
        let updated = current_secret(store, project, &profile.id, id)?
            .ok_or_else(|| reject("value disappeared"))?;
        store.connection().execute("INSERT INTO team_sync_values VALUES (?1,?2,?3) ON CONFLICT(project_id,secret_id) DO UPDATE SET digest=excluded.digest",params![project,id,digest(&serde_json::to_vec(&updated)?)])?;
        store.connection().execute(
            "DELETE FROM team_sync_conflicts WHERE project_id=?1 AND secret_id=?2",
            (project, id),
        )?;
    }
    Ok(())
}

/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn remove_member(
    store: &mut Store,
    project: &str,
    member: &str,
    master: &KeyBytes,
    now: i64,
) -> Result<Vec<String>> {
    store.with_atomic_write(|store| {
        let (team, owner) = local_owner(store, project)?;
        let members = roster(store, project, &team)?;
        let target = members.iter().find(|m| m.id == member)
            .or_else(|| members.iter().find(|m| m.name == member))
            .ok_or_else(|| reject("member not found"))?;
        if target.device == owner {
            return Err(reject("cannot remove this member"));
        }
        let mut snapshots = target
            .profiles
            .iter()
            .map(|id| profile_snapshot(store, project, id, master))
            .collect::<Result<Vec<_>>>()?;
        let names = snapshots
            .iter()
            .flat_map(|p| p.secrets.iter().filter(|s| !s.deleted).map(|s| s.name.clone()))
            .collect();
        for profile in &mut snapshots {
            let old=zeroize::Zeroizing::new(profile.secret_key);
            profile.secret_key = *locket_crypto::generate_key()?;
            profile.fingerprint_key = *locket_crypto::generate_key()?;
            profile.key_epoch=profile.key_epoch.checked_add(1).ok_or_else(||reject("key epoch overflow"))?;
            rekey_profile(store,project,profile,&old)?;
            store_key(store,project,Some(&profile.id),KeyPurpose::ProfileSecret,master,&profile.secret_key,now)?;
            store_key(store,project,Some(&profile.id),KeyPurpose::ProfileFingerprint,master,&profile.fingerprint_key,now)?;
            store.connection().execute("INSERT INTO team_sync_profile_epochs VALUES (?1,?2,?3) ON CONFLICT(project_id,profile_id) DO UPDATE SET epoch=excluded.epoch",params![project,profile.id,profile.key_epoch])?;
        }
        store.remove_team_member(&target.id,nanos(now)?)?;
        store.connection().execute("UPDATE devices SET revoked_at=COALESCE(revoked_at,?2) WHERE id=?1",params![target.device.id,nanos(now)?])?;
        audit_event(store,project,master,"TEAM_SYNC_REMOVE",now,&serde_json::json!({"member_id":target.id,"profile_count":snapshots.len()}))?;
        Ok(names)
    })
}

pub(super) fn audit_event(
    store: &mut Store,
    project: &str,
    master: &KeyBytes,
    action: &str,
    now: i64,
    details: &serde_json::Value,
) -> Result<()> {
    if store.get_key_by_scope(project, None, KeyPurpose::Audit.as_str())?.is_none() {
        return Ok(());
    }
    let key = load_key(store, project, None, KeyPurpose::Audit, master)?;
    store.append_audit(key.as_ref(),&AuditWrite{project_id:project,profile_id:None,action,status:"SUCCESS",secret_name:None,command:Some("team sync"),metadata_json:&serde_json::json!({"schema_version":2,"action":action,"status":"SUCCESS","command":"team sync","project_id":project,"details":details}),timestamp:nanos(now)?})?;
    Ok(())
}

/// Returns the authenticated first-join checkpoint for deterministic package selection.
/// # Errors
/// Rejects signatures, external pins, recipients, projects and expired first-join packages.
pub fn join_package_checkpoint(
    bytes: &[u8],
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    project: &str,
    pin: &str,
    now: i64,
) -> Result<(u64, String)> {
    let envelope = SignedStatement::open(bytes, sealing)?;
    let verified = envelope.verify(pin, project, local, now)?;
    Ok((verified.statement.epoch, verified.digest))
}

/// Lists profiles actually shared with an active non-owner recipient.
/// # Errors
/// Returns an error for an invalid owner anchor or inconsistent roster.
pub fn shared_profile_ids(store: &Store, project: &str) -> Result<Vec<String>> {
    let (team, owner) = local_owner(store, project)?;
    Ok(roster(store, project, &team)?
        .into_iter()
        .filter(|member| !member.removed && member.device != owner)
        .flat_map(|member| member.profiles)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn hold_reason(
    store: &Store,
    statement: &TeamStatement,
    profile: &TeamProfile,
    has_head: bool,
    allow_dangerous: bool,
) -> Result<Option<String>> {
    let locals = store.list_profiles(&statement.project_id)?;
    let local = locals.iter().find(|local| local.id == profile.id);
    if has_head
        && local.is_none()
        && let Some(collision) =
            locals.iter().find(|local| local.name == profile.name && local.id != profile.id)
        && !store.list_secrets_by_profile(&statement.project_id, &collision.id)?.is_empty()
    {
        return Ok(Some("profile-name-collision".into()));
    }
    if has_head {
        for secret in &profile.secrets {
            if store
                .get_secret_by_source(
                    &statement.project_id,
                    &profile.id,
                    &secret.name,
                    "team-managed",
                )?
                .is_some_and(|local| local.id != secret.id)
            {
                return Ok(Some("secret-name-collision".into()));
            }
        }
    }
    if !allow_dangerous && (profile.dangerous || local.is_some_and(|local| local.dangerous)) {
        return Ok(Some("consent-required".into()));
    }
    Ok(None)
}
fn apply_profile_or_hold(
    store: &Store,
    statement: &TeamStatement,
    profile: &TeamProfile,
    master: &KeyBytes,
    bytes: &[u8],
    result: &mut ApplyResult,
    has_head: bool,
    now: i64,
    allow_dangerous: bool,
) -> Result<()> {
    let reason = hold_reason(store, statement, profile, has_head, allow_dangerous)?;
    let mut retained_name = profile.clone();
    let local = store
        .list_profiles(&statement.project_id)?
        .into_iter()
        .find(|local| local.id == profile.id);
    if let Some(local) = &local {
        retained_name.name.clone_from(&local.name);
    }
    if let Some(reason) = reason {
        if reason != "profile-name-collision" || local.is_some() {
            apply_profile(
                store,
                statement,
                &retained_name,
                master,
                bytes,
                result,
                has_head,
                now,
                false,
            )?;
        }
        store.connection().execute(
            "INSERT INTO team_sync_pending_profiles VALUES (?1,?2,?3)",
            params![statement.project_id, profile.id, reason],
        )?;
        result.pending_profiles += 1;
        return Ok(());
    }
    apply_profile(store, statement, &retained_name, master, bytes, result, has_head, now, true)
}

/// Retries pending values against the current checkpoint and current local consent.
/// Caller must independently reconcile local name collisions; retry never renames or deletes them.
/// # Errors
/// Rejects stale checkpoints, revoked scope, invalid ciphertext or expired commit authorization.
pub fn resume_pending_profiles_guarded(
    store: &mut Store,
    project: &str,
    master: &KeyBytes,
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    allow_dangerous: bool,
    now: i64,
    authorization: Option<&CommitAuthorization>,
) -> Result<ApplyResult> {
    let active = store
        .get_active_local_device(project)?
        .ok_or_else(|| reject("active local device missing"))?;
    if identity(&active)? != *local {
        return Err(reject("recipient differs from active local device"));
    }
    let pending:Option<(i64,String,Vec<u8>)>=store.connection().query_row("SELECT epoch,digest,encrypted_package FROM team_sync_pending_packages WHERE project_id=?1",[project],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
    let Some((epoch, hash, bytes)) = pending else {
        return Ok(ApplyResult::default());
    };
    let (_, owner) = anchor(store, project)?.ok_or_else(|| reject("owner pin missing"))?;
    let envelope = SignedStatement::open(&bytes, sealing)?;
    let verified = envelope.verify_update(&owner.fingerprint, project, local, now)?;
    if epoch != i64::try_from(verified.statement.epoch).map_err(|_| reject("epoch overflow"))?
        || hash != verified.digest
    {
        return Err(reject("pending checkpoint mismatch"));
    }
    super::pending::current_checkpoint(store, project, &verified)?;
    for profile in &verified.statement.profiles {
        for secret in &profile.secrets {
            plaintext(project, profile, secret)?;
        }
    }
    let old_reasons=store.connection().prepare("SELECT profile_id,reason FROM team_sync_pending_profiles WHERE project_id=?1 ORDER BY profile_id")?.query_map([project],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?.collect::<std::result::Result<BTreeMap<_,_>,_>>()?;
    let mut new_reasons = BTreeMap::new();
    for id in old_reasons.keys() {
        let profile = verified
            .statement
            .profiles
            .iter()
            .find(|profile| &profile.id == id)
            .ok_or_else(|| reject("pending profile no longer granted"))?;
        if let Some(reason) =
            hold_reason(store, &verified.statement, profile, true, allow_dangerous)?
        {
            new_reasons.insert(id.clone(), reason);
        }
    }
    if old_reasons == new_reasons {
        return Ok(ApplyResult { pending_profiles: old_reasons.len(), ..ApplyResult::default() });
    }
    let _authorization = authorization.map(|authorize| authorize()).transpose()?;
    store.with_atomic_write(|store| {
        let head:(i64,String,String)=store.connection().query_row("SELECT epoch,digest,state FROM team_sync_heads WHERE project_id=?1",[project],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
        if head.0!=epoch || head.1!=hash || head.2=="fork" || head.2=="removed" {return Err(reject("pending package is not the current authorized checkpoint"));}
        let ids=store.connection().prepare("SELECT profile_id FROM team_sync_pending_profiles WHERE project_id=?1 ORDER BY profile_id")?.query_map([project],|row|row.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
        store.connection().execute("DELETE FROM team_sync_pending_profiles WHERE project_id=?1",[project])?;
        let mut result=ApplyResult::default();
        for id in ids {
            let profile=verified.statement.profiles.iter().find(|profile|profile.id==id).ok_or_else(||reject("pending profile no longer granted"))?;
            apply_profile_or_hold(store,&verified.statement,profile,master,&bytes,&mut result,true,now,allow_dangerous)?;
        }
        if result.pending_profiles==0 {store.connection().execute("DELETE FROM team_sync_pending_packages WHERE project_id=?1",[project])?;}
        store.connection().execute("UPDATE team_sync_heads SET state=?2 WHERE project_id=?1",params![project,if result.pending_profiles>0 {"pending-values"}else{"verified"}])?;
        audit_event(store,project,master,"TEAM_SYNC",now,&serde_json::json!({"pending_retry":true,"applied":result.applied,"pending_profiles":result.pending_profiles}))?;
        Ok(result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: &str, device: DeviceIdentity, role: &str) -> TeamMember {
        TeamMember {
            id: id.into(),
            name: id.into(),
            role: role.into(),
            profiles: Vec::new(),
            device,
            removed: false,
        }
    }

    #[test]
    fn roster_omission_preserves_the_device_and_membership_binding()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut store = Store::open(directory.path().join("roster.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "project", 1)?;
        store.insert_team(&TeamRecord {
            id: "team".into(),
            project_id: "project".into(),
            name: "team".into(),
            created_at: 1,
            updated_at: 1,
        })?;
        let owner = DeviceIdentity::new("owner".into(), [4; 32], [5; 32]);
        let observer = DeviceIdentity::new("observer".into(), [6; 32], [7; 32]);
        let omitted = member("historical-member", observer.clone(), "developer");
        let mut statement = TeamStatement {
            v: 1,
            team_id: "team".into(),
            project_id: "project".into(),
            epoch: 1,
            previous_digest: String::new(),
            issued_at: 1,
            expires_at: 60,
            nonce: [0; 24],
            publisher: owner.clone(),
            recipient: observer.clone(),
            members: vec![member("owner-member", owner, "owner"), omitted.clone()],
            profiles: Vec::new(),
        };

        validate_roster_transition(&store, &statement, None)?;
        apply_roster(&store, &statement, 1)?;
        statement.members.pop();
        validate_roster_transition(&store, &statement, None)?;
        apply_roster(&store, &statement, 2)?;
        let removed = store.get_team_member("team", &omitted.id)?.ok_or("missing tombstone")?;
        assert_eq!(removed.removed_at, Some(nanos(2)?));

        let new_device = DeviceIdentity::new("replacement".into(), [8; 32], [9; 32]);
        statement.members.push(member("fresh-member", new_device, "developer"));
        validate_roster_transition(&store, &statement, None)?;
        let replacement = statement.members.last_mut().ok_or("missing replacement")?;
        replacement.id.clone_from(&omitted.id);
        assert!(matches!(
            validate_roster_transition(&store, &statement, None),
            Err(super::super::SyncError::Rejected(message))
                if message == "member ID cannot change device identity"
        ));

        let replacement = statement.members.last_mut().ok_or("missing replacement")?;
        replacement.id = "fresh-member".into();
        replacement.device =
            DeviceIdentity::new("replacement".into(), [8; 32], observer.sealing_key);
        assert!(matches!(
            validate_roster_transition(&store, &statement, None),
            Err(super::super::SyncError::Rejected(message))
                if message == "removed membership cannot be reinstated"
        ));
        assert_eq!(store.get_team_member("team", &omitted.id)?, Some(removed));
        Ok(())
    }
}
