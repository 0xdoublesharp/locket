//! Metadata-only device and team-member directory RPC payloads.

use std::path::PathBuf;

use locket_core::privacy_alias;
use locket_store::{DeviceRecord, Store, StoreError, TeamMemberListRecord};
use serde::{Deserialize, Serialize};

/// Wire payload for the `ListDeviceMembers` RPC.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListDeviceMembersRequest {
    /// `SQLite` store path to read.
    pub store_path: PathBuf,
    /// Project id whose devices and team members are listed.
    pub project_id: String,
    /// Whether member, device, and fingerprint labels should be aliased.
    #[serde(default)]
    pub redact_names: bool,
    /// Whether revoked devices should be returned.
    #[serde(default = "default_true")]
    pub include_revoked_devices: bool,
}

/// Metadata-only `ListDeviceMembers` response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListDeviceMembersResponse {
    /// Device and team-member rows ordered by type and creation time.
    pub rows: Vec<DeviceMemberRow>,
}

/// Row kind for the desktop device/member directory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceMemberKind {
    /// Trusted device row.
    Device,
    /// Team member row.
    Member,
}

/// Metadata-only device/member directory row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceMemberRow {
    /// Stable row id.
    pub id: String,
    /// Row kind.
    pub kind: DeviceMemberKind,
    /// Display name or privacy alias.
    pub name: String,
    /// Privacy alias when redaction is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Team role for member rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Device fingerprint or privacy alias.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Fingerprint alias when redaction is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_alias: Option<String>,
    /// Trusted-device count for member rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_device_count: Option<u32>,
    /// Whether this device row is the active local device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_device: Option<bool>,
    /// Metadata status label: `active`, `revoked`, or `removed`.
    pub status: String,
    /// Creation or join timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last-seen timestamp in nanoseconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
}

/// Lists device/member metadata. This never reads private keys or secret values.
///
/// # Errors
///
/// Returns [`StoreError`] when the store cannot be opened or queried.
pub fn list_device_members_from_store(
    store: &Store,
    request: &ListDeviceMembersRequest,
) -> Result<ListDeviceMembersResponse, StoreError> {
    let mut rows = store
        .list_devices(&request.project_id, request.include_revoked_devices)?
        .into_iter()
        .map(|device| device_row(device, request.redact_names))
        .collect::<Vec<_>>();

    if let Some(team) = store.get_team_by_project(&request.project_id)? {
        rows.extend(
            store
                .list_team_members(&team.id)?
                .into_iter()
                .map(|member| member_row(member, request.redact_names)),
        );
    }

    rows.sort_by(|left, right| {
        kind_sort(left.kind)
            .cmp(&kind_sort(right.kind))
            .then_with(|| left.created_at.cmp(&right.created_at))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(ListDeviceMembersResponse { rows })
}

fn device_row(device: DeviceRecord, redact_names: bool) -> DeviceMemberRow {
    let alias = redact_names.then(|| privacy_alias("device", &device.name));
    let fingerprint_alias = redact_names.then(|| privacy_alias("fingerprint", &device.fingerprint));
    DeviceMemberRow {
        id: device.id,
        kind: DeviceMemberKind::Device,
        name: alias.clone().unwrap_or(device.name),
        alias,
        role: None,
        fingerprint: Some(fingerprint_alias.clone().unwrap_or(device.fingerprint)),
        fingerprint_alias,
        trusted_device_count: None,
        local_device: Some(device.local),
        status: if device.revoked_at.is_some() { "revoked" } else { "active" }.to_owned(),
        created_at: device.created_at,
        last_seen_at: device.last_seen_at,
    }
}

fn member_row(member: TeamMemberListRecord, redact_names: bool) -> DeviceMemberRow {
    let alias = redact_names.then(|| privacy_alias("member", &member.display_name));
    DeviceMemberRow {
        id: member.id,
        kind: DeviceMemberKind::Member,
        name: alias.clone().unwrap_or(member.display_name),
        alias,
        role: Some(member.role),
        fingerprint: None,
        fingerprint_alias: None,
        trusted_device_count: u32::try_from(member.trusted_device_count).ok(),
        local_device: None,
        status: if member.removed_at.is_some() { "removed" } else { "active" }.to_owned(),
        created_at: member.joined_at,
        last_seen_at: None,
    }
}

const fn default_true() -> bool {
    true
}

const fn kind_sort(kind: DeviceMemberKind) -> u8 {
    match kind {
        DeviceMemberKind::Device => 0,
        DeviceMemberKind::Member => 1,
    }
}
