//! V1 agent RPC method registry and wire-name parsing.

use std::str::FromStr;

use thiserror::Error;

/// V1 agent RPC method names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentMethod {
    /// Read team synchronization status.
    TeamSyncStatus,
    /// Configure an explicitly selected encrypted package transport.
    TeamSyncConfigure,
    /// Remove the local team delivery configuration and credentials.
    TeamSyncClear,
    /// Process encrypted team updates with a live local grant.
    TeamSyncNow,
    /// Test listing the configured package transport with a live local grant.
    TeamSyncTestRemote,
    /// Resolve a verified incoming profile collision using explicit local consent.
    TeamSyncReconcile,
    /// Return metadata-only agent status.
    Status,
    /// Unlock local key material.
    Unlock,
    /// Unlock several local vaults with a single user-verification ceremony.
    UnlockBatch,
    /// Clear local key material and live grants.
    Lock,
    /// Gracefully stop the local daemon after clearing key material.
    Shutdown,
    /// Register an automation client.
    RegisterClient,
    /// Revoke an automation client.
    RevokeClient,
    /// Request a live TTL grant.
    RequestGrant,
    /// Revoke a live TTL grant.
    RevokeGrant,
    /// Lazily record an expired grant.
    ExpireGrant,
    /// Resolve an authorized `lk://` reference.
    ResolveReference,
    /// Prepare a command policy for execution.
    PrepareExec,
    /// Provide known-value scan matching.
    ScanKnownValues,
    /// List metadata-only runtime session rows.
    ListRuntimeSessions,
    /// List metadata-only saved command policy rows.
    ListPolicies,
    /// List metadata-only device and team-member rows.
    ListDeviceMembers,
    /// Reveal one secret value through a gated path.
    Reveal,
    /// Copy one secret value through a gated path.
    Copy,
    /// Verify the local audit HMAC chain.
    VerifyAudit,
    /// List metadata-only audit rows.
    ListAudit,
    /// Read metadata-only desktop settings.
    ReadConfig,
    /// Write desktop settings and audit/profile metadata.
    WriteConfig,
    /// Subscribe to metadata-only status events.
    SubscribeStatus,
    /// Cancel a status subscription.
    CancelSubscription,
    /// Automation client challenge handshake.
    ClientHello,
    /// Return metadata-only active-profile secret rows.
    ListSecrets,
    /// Return metadata-only local project summaries.
    ListProjects,
    /// Discover secret metadata across local projects.
    DiscoverSecrets,
    /// Return metadata-only secret version rows.
    ListVersions,
    /// Create or rotate one secret value through a gated path.
    SetSecret,
    /// Create an environment in a trusted folder project.
    CreateProfile,
    /// Tombstone one active secret source.
    DeleteSecret,
    /// Promote an active secret to the Global Vault inside the agent.
    CopySecretToShared,
    /// Link a project secret name to an active Global Vault secret.
    LinkSecret,
    /// Remove a project secret link to the Global Vault.
    UnlinkSecret,
    /// List projects linked to a Global Vault secret (metadata-only).
    ListSharedUsages,
    /// List cross-project duplicate value groups from local dedup tags (metadata-only).
    ListDuplicates,
    /// Import a selected dotenv file with an agent-owned key.
    ImportDotenv,
    /// Persist a selected project policy edit.
    ApplyPolicy,
    /// Switch the active project profile.
    SetActiveProfile,
    /// Register a names-only IDE env-session map for an integrated terminal.
    RegisterIdeEnvSession,
    /// Look up a registered IDE env-session by its `LOCKET_IDE_ENV_SESSION` UUID.
    IdeEnvSession,
    /// Replace the agent's in-memory command policy snapshot for a project.
    RegisterCommandPolicies,
    /// Dry-run validate a command policy through the agent.
    PolicyDoctor,
    /// Export a sealed backup bundle through the desktop agent path.
    ExportBundle,
    /// Import a sealed backup bundle through the desktop agent path.
    ImportBundle,
    /// Verify a sealed backup bundle through the desktop agent path.
    VerifyBundle,
    /// Rotate the recovery code through the desktop agent path.
    RecoveryRotate,
}

impl AgentMethod {
    /// Returns the exact v1 wire method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TeamSyncStatus => "TeamSyncStatus",
            Self::TeamSyncConfigure => "TeamSyncConfigure",
            Self::TeamSyncClear => "team_sync.clear",
            Self::TeamSyncNow => "TeamSyncNow",
            Self::TeamSyncTestRemote => "team_sync.test_remote",
            Self::TeamSyncReconcile => "TeamSyncReconcile",
            Self::Status => "Status",
            Self::Unlock => "Unlock",
            Self::UnlockBatch => "unlock_batch",
            Self::Lock => "Lock",
            Self::Shutdown => "Shutdown",
            Self::RegisterClient => "RegisterClient",
            Self::RevokeClient => "RevokeClient",
            Self::RequestGrant => "RequestGrant",
            Self::RevokeGrant => "RevokeGrant",
            Self::ExpireGrant => "ExpireGrant",
            Self::ResolveReference => "ResolveReference",
            Self::PrepareExec => "PrepareExec",
            Self::ScanKnownValues => "ScanKnownValues",
            Self::ListRuntimeSessions => "ListRuntimeSessions",
            Self::ListPolicies => "ListPolicies",
            Self::ListDeviceMembers => "ListDeviceMembers",
            Self::Reveal => "Reveal",
            Self::Copy => "Copy",
            Self::VerifyAudit => "VerifyAudit",
            Self::ListAudit => "ListAudit",
            Self::ReadConfig => "ReadConfig",
            Self::WriteConfig => "WriteConfig",
            Self::SubscribeStatus => "SubscribeStatus",
            Self::CancelSubscription => "CancelSubscription",
            Self::ClientHello => "ClientHello",
            Self::ListSecrets => "ListSecrets",
            Self::ListProjects => "ListProjects",
            Self::DiscoverSecrets => "DiscoverSecrets",
            Self::ListVersions => "ListVersions",
            Self::SetSecret => "SetSecret",
            Self::CreateProfile => "CreateProfile",
            Self::DeleteSecret => "DeleteSecret",
            Self::CopySecretToShared => "CopySecretToShared",
            Self::LinkSecret => "LinkSecret",
            Self::UnlinkSecret => "UnlinkSecret",
            Self::ListSharedUsages => "ListSharedUsages",
            Self::ListDuplicates => "ListDuplicates",
            Self::ImportDotenv => "ImportDotenv",
            Self::ApplyPolicy => "ApplyPolicy",
            Self::SetActiveProfile => "SetActiveProfile",
            Self::RegisterIdeEnvSession => "RegisterIdeEnvSession",
            Self::IdeEnvSession => "IdeEnvSession",
            Self::RegisterCommandPolicies => "RegisterCommandPolicies",
            Self::PolicyDoctor => "PolicyDoctor",
            Self::ExportBundle => "ExportBundle",
            Self::ImportBundle => "ImportBundle",
            Self::VerifyBundle => "VerifyBundle",
            Self::RecoveryRotate => "RecoveryRotate",
        }
    }
}

impl FromStr for AgentMethod {
    type Err = UnknownMethod;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "TeamSyncStatus" => Ok(Self::TeamSyncStatus),
            "TeamSyncConfigure" => Ok(Self::TeamSyncConfigure),
            "team_sync.clear" => Ok(Self::TeamSyncClear),
            "TeamSyncNow" => Ok(Self::TeamSyncNow),
            "team_sync.test_remote" => Ok(Self::TeamSyncTestRemote),
            "TeamSyncReconcile" => Ok(Self::TeamSyncReconcile),
            "Status" => Ok(Self::Status),
            "Unlock" => Ok(Self::Unlock),
            "unlock_batch" => Ok(Self::UnlockBatch),
            "Lock" => Ok(Self::Lock),
            "Shutdown" => Ok(Self::Shutdown),
            "RegisterClient" => Ok(Self::RegisterClient),
            "RevokeClient" => Ok(Self::RevokeClient),
            "RequestGrant" => Ok(Self::RequestGrant),
            "RevokeGrant" => Ok(Self::RevokeGrant),
            "ExpireGrant" => Ok(Self::ExpireGrant),
            "ResolveReference" => Ok(Self::ResolveReference),
            "PrepareExec" => Ok(Self::PrepareExec),
            "ScanKnownValues" => Ok(Self::ScanKnownValues),
            "ListRuntimeSessions" => Ok(Self::ListRuntimeSessions),
            "ListPolicies" => Ok(Self::ListPolicies),
            "ListDeviceMembers" => Ok(Self::ListDeviceMembers),
            "Reveal" => Ok(Self::Reveal),
            "Copy" => Ok(Self::Copy),
            "VerifyAudit" => Ok(Self::VerifyAudit),
            "ListAudit" => Ok(Self::ListAudit),
            "ReadConfig" => Ok(Self::ReadConfig),
            "WriteConfig" => Ok(Self::WriteConfig),
            "SubscribeStatus" => Ok(Self::SubscribeStatus),
            "CancelSubscription" => Ok(Self::CancelSubscription),
            "ClientHello" => Ok(Self::ClientHello),
            "ListSecrets" => Ok(Self::ListSecrets),
            "ListProjects" => Ok(Self::ListProjects),
            "DiscoverSecrets" => Ok(Self::DiscoverSecrets),
            "ListVersions" => Ok(Self::ListVersions),
            "SetSecret" => Ok(Self::SetSecret),
            "CreateProfile" => Ok(Self::CreateProfile),
            "DeleteSecret" => Ok(Self::DeleteSecret),
            "CopySecretToShared" => Ok(Self::CopySecretToShared),
            "LinkSecret" => Ok(Self::LinkSecret),
            "UnlinkSecret" => Ok(Self::UnlinkSecret),
            "ListSharedUsages" => Ok(Self::ListSharedUsages),
            "ListDuplicates" => Ok(Self::ListDuplicates),
            "ImportDotenv" => Ok(Self::ImportDotenv),
            "ApplyPolicy" => Ok(Self::ApplyPolicy),
            "SetActiveProfile" => Ok(Self::SetActiveProfile),
            "RegisterIdeEnvSession" => Ok(Self::RegisterIdeEnvSession),
            "IdeEnvSession" => Ok(Self::IdeEnvSession),
            "RegisterCommandPolicies" => Ok(Self::RegisterCommandPolicies),
            "PolicyDoctor" => Ok(Self::PolicyDoctor),
            "ExportBundle" => Ok(Self::ExportBundle),
            "ImportBundle" => Ok(Self::ImportBundle),
            "VerifyBundle" => Ok(Self::VerifyBundle),
            "RecoveryRotate" => Ok(Self::RecoveryRotate),
            other => Err(UnknownMethod { method: other.to_owned() }),
        }
    }
}

/// Unknown v1 agent method name.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("unknown agent method: {method}")]
pub struct UnknownMethod {
    /// Method string found in the envelope.
    pub method: String,
}

#[cfg(test)]
mod tests {
    use super::AgentMethod;

    #[test]
    fn desktop_crud_methods_round_trip() {
        for name in ["CreateProfile", "DeleteSecret", "CopySecretToShared"] {
            assert_eq!(name.parse::<AgentMethod>().map(AgentMethod::as_str), Ok(name));
        }
    }
}
