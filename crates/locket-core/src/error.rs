//! Centralized Locket errors and stable process exit codes.

use thiserror::Error;

/// A process exit code reserved by the Locket failure-mode specification.
pub type ExitCode = u8;

/// Typed Locket failure modes.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
pub enum LocketError {
    /// Invalid `lk://` reference syntax or target.
    #[error("invalid locket reference")]
    InvalidReference,
    /// A Git worktree was required but not found.
    #[error("git worktree required")]
    GitWorktreeRequired,
    /// User-supplied secret name failed `SecretName` validation.
    #[error("invalid secret name")]
    InvalidSecretName,
    /// User-supplied profile name failed `ProfileName` validation.
    #[error("invalid profile name")]
    InvalidProfileName,
    /// Policy validation could not complete without an agent or unlocked vault.
    #[error("policy validation incomplete")]
    PolicyValidationIncomplete,
    /// Policy TOML is structurally invalid (parse, type, or value error).
    #[error("invalid policy")]
    InvalidPolicy,
    /// Referenced command policy or automation-client policy binding was not found.
    #[error("policy not found")]
    PolicyNotFound,
    /// Environment variable conflict under `override = \"error\"`.
    #[error("environment conflict")]
    EnvironmentConflict,
    /// Metadata contains invalid display characters.
    #[error("metadata invalid")]
    MetadataInvalid,
    /// Metadata looks like secret material.
    #[error("metadata looks like secret")]
    MetadataLooksLikeSecret,
    /// Typed-string confirmation prompt rejected by the user input.
    #[error("confirmation did not match")]
    ConfirmationFailed,
    /// Interactive terminal input was required but unavailable.
    #[error("interactive TTY required")]
    TtyRequired,
    /// `locket scan` found one or more blocking findings.
    #[error("scan blocked by findings")]
    ScanFindingBlocked,
    /// Secret, profile, policy, or key material already exists.
    #[error("secret already exists")]
    SecretAlreadyExists,
    /// Policy, role, profile, or command scope explicitly denied the action.
    #[error("access denied")]
    AccessDenied,
    /// Read against a dangerous profile requires explicit `--use-dangerous` consent.
    #[error("dangerous profile confirmation required")]
    DangerousProfileConfirmationRequired,
    /// Caller's team role does not permit this team management action.
    #[error("team role denied")]
    TeamRoleDenied,
    /// Project root is not trusted.
    #[error("project root untrusted")]
    ProjectRootUntrusted,
    /// No Locket project could be resolved from the current directory.
    #[error("project not found")]
    ProjectNotFound,
    /// Vault or required key is locked.
    #[error("unlock required")]
    UnlockRequired,
    /// No live grant covers this action or context.
    #[error("grant required")]
    GrantRequired,
    /// Local user verification failed.
    #[error("local user verification failed")]
    UserVerificationFailed,
    /// Pinned deprecated secret version has no active grace window.
    #[error("secret version expired")]
    SecretVersionExpired,
    /// Selected secret source is tombstoned.
    #[error("secret deleted")]
    SecretDeleted,
    /// Selected secret could not be found by name/source/profile.
    #[error("secret not found")]
    SecretNotFound,
    /// Selected profile could not be found by name.
    #[error("profile not found")]
    ProfileNotFound,
    /// Required agent is unavailable.
    #[error("agent unavailable")]
    AgentUnavailable,
    /// Agent socket is in use by a peer that is not the active trusted agent.
    #[error("agent socket in use")]
    AgentSocketInUse,
    /// Automation client is not trusted.
    #[error("automation client not trusted")]
    AutomationClientNotTrusted,
    /// Automation client replay was detected.
    #[error("automation client replay detected")]
    AutomationClientReplayDetected,
    /// External environment source could not be resolved.
    #[error("external source unavailable")]
    ExternalSourceUnavailable,
    /// IDE-published env-session is not available because the agent-side handler
    /// or the VS Code-side producer has not delivered a session map for this
    /// project, profile, or terminal session.
    #[error("ide env session unavailable")]
    IdeEnvSessionUnavailable,
    /// Update manifest signature, schema, or metadata validation failed.
    #[error("update manifest invalid")]
    UpdateManifestInvalid,
    /// Secret version counter cannot be advanced.
    #[error("secret version overflow")]
    SecretVersionOverflow,
    /// Database contents are corrupt.
    #[error("corrupt database")]
    CorruptDb,
    /// Another Locket process is currently writing.
    #[error("storage busy")]
    StorageBusy,
    /// Store schema is newer than this binary supports.
    #[error("schema newer than binary")]
    SchemaNewerThanBinary,
    /// Audit chain verification failed.
    #[error("audit integrity failed")]
    AuditIntegrityFailed,
    /// Keychain is unavailable.
    #[error("keychain unavailable")]
    KeychainUnavailable,
    /// Recovery code is lost.
    #[error("lost recovery code")]
    LostRecoveryCode,
    /// Keychain entry is lost.
    #[error("lost keychain entry")]
    LostKeychainEntry,
    /// Recovery code and keychain entry are both lost.
    #[error("vault unrecoverable")]
    UnrecoverableVault,
    /// Sealed bundle verification failed.
    #[error("bundle verification failed")]
    BundleVerificationFailed,
    /// Invite has expired.
    #[error("invite expired")]
    InviteExpired,
    /// Team bundle conflicts with local state.
    #[error("team bundle conflict")]
    TeamBundleConflict,
    /// Device has been revoked.
    #[error("device revoked")]
    DeviceRevoked,
    /// Invite replay was detected (invite id already accepted).
    #[error("invite replay detected")]
    ReplayDetected,
    /// Device descriptor is structurally invalid or has a mismatched fingerprint.
    #[error("device descriptor invalid")]
    DeviceDescriptorInvalid,
    /// Invite signature is invalid or was not produced by the claimed issuer key.
    #[error("invite signature invalid")]
    InviteSignatureInvalid,
}

/// Safe display copy for a typed Locket failure.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ErrorDisplayCopy {
    /// Short user-facing reason. Never includes secret values.
    pub reason: &'static str,
    /// One safe next action, phrased consistently across surfaces.
    pub next_action: &'static str,
}

impl LocketError {
    /// Parses the stable agent/API error code name for a typed failure.
    #[must_use]
    pub const fn from_code_name(name: &str) -> Option<Self> {
        match name.as_bytes() {
            b"InvalidReference" => Some(Self::InvalidReference),
            b"GitWorktreeRequired" => Some(Self::GitWorktreeRequired),
            b"InvalidSecretName" => Some(Self::InvalidSecretName),
            b"InvalidProfileName" => Some(Self::InvalidProfileName),
            b"PolicyValidationIncomplete" => Some(Self::PolicyValidationIncomplete),
            b"InvalidPolicy" => Some(Self::InvalidPolicy),
            b"PolicyNotFound" => Some(Self::PolicyNotFound),
            b"EnvironmentConflict" => Some(Self::EnvironmentConflict),
            b"MetadataInvalid" => Some(Self::MetadataInvalid),
            b"MetadataLooksLikeSecret" => Some(Self::MetadataLooksLikeSecret),
            b"ConfirmationFailed" => Some(Self::ConfirmationFailed),
            b"TtyRequired" => Some(Self::TtyRequired),
            b"ScanFindingBlocked" => Some(Self::ScanFindingBlocked),
            b"SecretAlreadyExists" => Some(Self::SecretAlreadyExists),
            b"AccessDenied" => Some(Self::AccessDenied),
            b"DangerousProfileConfirmationRequired" => {
                Some(Self::DangerousProfileConfirmationRequired)
            }
            b"TeamRoleDenied" => Some(Self::TeamRoleDenied),
            b"ProjectRootUntrusted" => Some(Self::ProjectRootUntrusted),
            b"ProjectNotFound" => Some(Self::ProjectNotFound),
            b"UnlockRequired" => Some(Self::UnlockRequired),
            b"GrantRequired" => Some(Self::GrantRequired),
            b"UserVerificationFailed" => Some(Self::UserVerificationFailed),
            b"SecretVersionExpired" => Some(Self::SecretVersionExpired),
            b"SecretDeleted" => Some(Self::SecretDeleted),
            b"SecretNotFound" => Some(Self::SecretNotFound),
            b"ProfileNotFound" => Some(Self::ProfileNotFound),
            b"AgentUnavailable" => Some(Self::AgentUnavailable),
            b"AgentSocketInUse" => Some(Self::AgentSocketInUse),
            b"AutomationClientNotTrusted" => Some(Self::AutomationClientNotTrusted),
            b"AutomationClientReplayDetected" => Some(Self::AutomationClientReplayDetected),
            b"ExternalSourceUnavailable" => Some(Self::ExternalSourceUnavailable),
            b"IdeEnvSessionUnavailable" => Some(Self::IdeEnvSessionUnavailable),
            b"UpdateManifestInvalid" => Some(Self::UpdateManifestInvalid),
            b"SecretVersionOverflow" => Some(Self::SecretVersionOverflow),
            b"CorruptDb" => Some(Self::CorruptDb),
            b"StorageBusy" => Some(Self::StorageBusy),
            b"SchemaNewerThanBinary" => Some(Self::SchemaNewerThanBinary),
            b"AuditIntegrityFailed" => Some(Self::AuditIntegrityFailed),
            b"KeychainUnavailable" => Some(Self::KeychainUnavailable),
            b"LostRecoveryCode" => Some(Self::LostRecoveryCode),
            b"LostKeychainEntry" => Some(Self::LostKeychainEntry),
            b"UnrecoverableVault" => Some(Self::UnrecoverableVault),
            b"BundleVerificationFailed" => Some(Self::BundleVerificationFailed),
            b"InviteExpired" => Some(Self::InviteExpired),
            b"TeamBundleConflict" => Some(Self::TeamBundleConflict),
            b"DeviceRevoked" => Some(Self::DeviceRevoked),
            b"ReplayDetected" => Some(Self::ReplayDetected),
            b"DeviceDescriptorInvalid" => Some(Self::DeviceDescriptorInvalid),
            b"InviteSignatureInvalid" => Some(Self::InviteSignatureInvalid),
            _ => None,
        }
    }

    /// Returns user-facing copy shared by CLI, desktop, tray, and editor surfaces.
    #[must_use]
    pub const fn display_copy(&self) -> ErrorDisplayCopy {
        match self.display_copy_input_policy() {
            Some(copy) => copy,
            None => match self.display_copy_runtime_agent() {
                Some(copy) => copy,
                None => self.display_copy_storage_team(),
            },
        }
    }

    const fn display_copy_input_policy(self) -> Option<ErrorDisplayCopy> {
        match self {
            Self::InvalidReference => Some(ErrorDisplayCopy {
                reason: "The Locket reference is invalid.",
                next_action: "Fix the reference syntax, profile, key, source, or version.",
            }),
            Self::GitWorktreeRequired => Some(ErrorDisplayCopy {
                reason: "This command requires a Git worktree.",
                next_action: "Run the command inside a Git worktree or scan an explicit path.",
            }),
            Self::InvalidSecretName => Some(ErrorDisplayCopy {
                reason: "The secret name is invalid.",
                next_action: "Use an uppercase environment-style name.",
            }),
            Self::InvalidProfileName => Some(ErrorDisplayCopy {
                reason: "The profile name is invalid.",
                next_action: "Use a lowercase profile name such as dev or staging.",
            }),
            Self::PolicyValidationIncomplete => Some(ErrorDisplayCopy {
                reason: "Policy validation could not finish.",
                next_action: "Start or unlock the agent, then rerun policy validation.",
            }),
            Self::InvalidPolicy => Some(ErrorDisplayCopy {
                reason: "The policy is invalid.",
                next_action: "Fix the policy document and retry.",
            }),
            Self::PolicyNotFound => Some(ErrorDisplayCopy {
                reason: "The policy was not found.",
                next_action: "Add the policy or choose an existing policy name.",
            }),
            Self::EnvironmentConflict => Some(ErrorDisplayCopy {
                reason: "Environment variable injection would overwrite a protected name.",
                next_action: "Rename the variable or change the policy override mode.",
            }),
            Self::MetadataInvalid => Some(ErrorDisplayCopy {
                reason: "Metadata is invalid.",
                next_action: "Remove unsupported characters or values and retry.",
            }),
            Self::MetadataLooksLikeSecret => Some(ErrorDisplayCopy {
                reason: "Metadata looks like secret material.",
                next_action: "Remove the secret-like metadata or store it as a secret.",
            }),
            Self::ConfirmationFailed => Some(ErrorDisplayCopy {
                reason: "The confirmation text did not match.",
                next_action: "Retry and type the requested confirmation exactly.",
            }),
            Self::TtyRequired => Some(ErrorDisplayCopy {
                reason: "An interactive terminal is required.",
                next_action: "Retry from an interactive terminal.",
            }),
            Self::ScanFindingBlocked => Some(ErrorDisplayCopy {
                reason: "Scan findings blocked the command.",
                next_action: "Review the findings, rotate exposed values, or suppress intentional matches.",
            }),
            Self::SecretAlreadyExists => Some(ErrorDisplayCopy {
                reason: "The secret already exists.",
                next_action: "Use rotate/update behavior or choose a different source.",
            }),
            _ => None,
        }
    }

    const fn display_copy_runtime_agent(self) -> Option<ErrorDisplayCopy> {
        match self {
            Self::AccessDenied => Some(ErrorDisplayCopy {
                reason: "Policy or trust rules denied the action.",
                next_action: "Request the required grant, policy change, or team role.",
            }),
            Self::DangerousProfileConfirmationRequired => Some(ErrorDisplayCopy {
                reason: "Reads against a profile marked dangerous require explicit consent.",
                next_action: "Re-run the command with --use-dangerous to confirm the dangerous profile read.",
            }),
            Self::TeamRoleDenied => Some(ErrorDisplayCopy {
                reason: "Your team role does not allow this action.",
                next_action: "Ask an owner or maintainer to perform or authorize the action.",
            }),
            Self::ProjectRootUntrusted => Some(ErrorDisplayCopy {
                reason: "The project root is not trusted.",
                next_action: "Run locket project trust-root from the intended project path.",
            }),
            Self::ProjectNotFound => Some(ErrorDisplayCopy {
                reason: "No Locket project was found.",
                next_action: "Run locket init or move into an existing Locket project.",
            }),
            Self::UnlockRequired => Some(ErrorDisplayCopy {
                reason: "The vault is locked.",
                next_action: "Run locket unlock or approve an agent unlock prompt.",
            }),
            Self::GrantRequired => Some(ErrorDisplayCopy {
                reason: "No live grant covers this action.",
                next_action: "Run locket allow or refresh the shell or editor grant.",
            }),
            Self::UserVerificationFailed => Some(ErrorDisplayCopy {
                reason: "Local user verification failed.",
                next_action: "Retry verification or use a configured recovery path.",
            }),
            Self::SecretVersionExpired => Some(ErrorDisplayCopy {
                reason: "The pinned secret version is expired.",
                next_action: "Update the reference to the current version or rotate with a new grace window.",
            }),
            Self::SecretDeleted => Some(ErrorDisplayCopy {
                reason: "The selected secret source is deleted.",
                next_action: "Choose another source or restore from a trusted backup.",
            }),
            Self::SecretNotFound => Some(ErrorDisplayCopy {
                reason: "The secret was not found.",
                next_action: "Check the secret name, profile, and source.",
            }),
            Self::ProfileNotFound => Some(ErrorDisplayCopy {
                reason: "The profile was not found.",
                next_action: "Choose an existing profile or create one.",
            }),
            Self::AgentUnavailable => Some(ErrorDisplayCopy {
                reason: "The local agent is unavailable.",
                next_action: "Run locket agent start, then retry.",
            }),
            Self::AgentSocketInUse => Some(ErrorDisplayCopy {
                reason: "The agent socket is already in use.",
                next_action: "Stop the stale agent or retry in direct CLI mode.",
            }),
            Self::AutomationClientNotTrusted => Some(ErrorDisplayCopy {
                reason: "The automation client is not trusted.",
                next_action: "Register the client or fix its policy scope.",
            }),
            Self::AutomationClientReplayDetected => Some(ErrorDisplayCopy {
                reason: "An automation client replay was detected.",
                next_action: "Retry with a fresh nonce and rotate the client key if replay is suspected.",
            }),
            Self::ExternalSourceUnavailable => Some(ErrorDisplayCopy {
                reason: "An external environment source is unavailable.",
                next_action: "Start or fix the external provider and retry.",
            }),
            Self::IdeEnvSessionUnavailable => Some(ErrorDisplayCopy {
                reason: "The IDE env-session is not available.",
                next_action: "Open the project in the Locket VS Code extension or retry once the agent IDE handler is running.",
            }),
            Self::UpdateManifestInvalid => Some(ErrorDisplayCopy {
                reason: "The update manifest is invalid.",
                next_action: "Refresh the manifest source or use a trusted release artifact.",
            }),
            Self::SecretVersionOverflow => Some(ErrorDisplayCopy {
                reason: "The secret version counter cannot advance.",
                next_action: "Inspect the store metadata before retrying.",
            }),
            _ => None,
        }
    }

    const fn display_copy_storage_team(self) -> ErrorDisplayCopy {
        match self {
            Self::CorruptDb => ErrorDisplayCopy {
                reason: "The local database appears corrupt.",
                next_action: "Run diagnostics and restore from a trusted backup if needed.",
            },
            Self::StorageBusy => ErrorDisplayCopy {
                reason: "Another Locket process is writing.",
                next_action: "Wait for the other command to finish, then retry.",
            },
            Self::SchemaNewerThanBinary => ErrorDisplayCopy {
                reason: "The store schema is newer than this binary supports.",
                next_action: "Upgrade Locket and retry.",
            },
            Self::AuditIntegrityFailed => ErrorDisplayCopy {
                reason: "Audit chain verification failed.",
                next_action: "Investigate store tampering or restore from backup.",
            },
            Self::KeychainUnavailable => ErrorDisplayCopy {
                reason: "The keychain is unavailable.",
                next_action: "Unlock with passphrase fallback or run recovery.",
            },
            Self::LostRecoveryCode => ErrorDisplayCopy {
                reason: "The recovery code is missing.",
                next_action: "Rotate recovery while the vault is still unlocked.",
            },
            Self::LostKeychainEntry => ErrorDisplayCopy {
                reason: "The keychain entry is missing.",
                next_action: "Run locket recover with the recovery code.",
            },
            Self::UnrecoverableVault => ErrorDisplayCopy {
                reason: "The vault cannot be recovered on this device.",
                next_action: "Restore from another trusted device or reinitialize the project.",
            },
            Self::BundleVerificationFailed => ErrorDisplayCopy {
                reason: "The sealed bundle failed verification.",
                next_action: "Request a fresh bundle or verify it on an addressed device.",
            },
            Self::InviteExpired => ErrorDisplayCopy {
                reason: "The invite has expired.",
                next_action: "Ask a maintainer for a fresh invite.",
            },
            Self::TeamBundleConflict => ErrorDisplayCopy {
                reason: "The team bundle conflicts with local state.",
                next_action: "Choose a metadata-only conflict resolution path.",
            },
            Self::DeviceRevoked => ErrorDisplayCopy {
                reason: "The device has been revoked.",
                next_action: "Add a new trusted device or request a fresh team invite.",
            },
            Self::ReplayDetected => ErrorDisplayCopy {
                reason: "A replayed invite or request was detected.",
                next_action: "Request a fresh invite or retry with a new nonce.",
            },
            Self::DeviceDescriptorInvalid => ErrorDisplayCopy {
                reason: "The device descriptor is invalid.",
                next_action: "Recreate the descriptor on the trusted device.",
            },
            Self::InviteSignatureInvalid => ErrorDisplayCopy {
                reason: "The invite signature is invalid.",
                next_action: "Reject the invite and request a new one from the issuer.",
            },
            _ => ErrorDisplayCopy {
                reason: "The Locket error is not mapped to display copy.",
                next_action: "Upgrade Locket or report the missing error mapping.",
            },
        }
    }

    /// Returns the stable process exit code for this failure.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidReference
            | Self::GitWorktreeRequired
            | Self::MetadataInvalid
            | Self::InvalidSecretName
            | Self::InvalidProfileName
            | Self::PolicyNotFound
            | Self::ProjectNotFound => 64,
            Self::PolicyValidationIncomplete | Self::InvalidPolicy => 65,
            Self::EnvironmentConflict | Self::MetadataLooksLikeSecret => 66,
            Self::SecretAlreadyExists => 67,
            Self::ConfirmationFailed | Self::TtyRequired => 68,
            Self::ScanFindingBlocked => 69,
            Self::AccessDenied
            | Self::TeamRoleDenied
            | Self::DangerousProfileConfirmationRequired => 70,
            Self::ProjectRootUntrusted => 71,
            Self::UnlockRequired => 72,
            Self::GrantRequired => 73,
            Self::UserVerificationFailed => 74,
            Self::SecretVersionExpired => 75,
            Self::SecretDeleted => 76,
            Self::SecretNotFound => 77,
            Self::ProfileNotFound => 78,
            Self::AgentUnavailable | Self::IdeEnvSessionUnavailable => 80,
            Self::AgentSocketInUse => 81,
            Self::AutomationClientNotTrusted => 82,
            Self::AutomationClientReplayDetected => 83,
            Self::ExternalSourceUnavailable | Self::UpdateManifestInvalid => 89,
            Self::SecretVersionOverflow | Self::CorruptDb => 90,
            Self::StorageBusy => 91,
            Self::SchemaNewerThanBinary => 92,
            Self::AuditIntegrityFailed => 93,
            Self::KeychainUnavailable => 100,
            Self::LostRecoveryCode => 101,
            Self::LostKeychainEntry => 102,
            Self::UnrecoverableVault => 103,
            Self::BundleVerificationFailed => 110,
            Self::InviteExpired => 111,
            Self::TeamBundleConflict => 112,
            Self::DeviceRevoked | Self::ReplayDetected | Self::DeviceDescriptorInvalid => 113,
            Self::InviteSignatureInvalid => 114,
        }
    }
}

impl From<&LocketError> for ExitCode {
    fn from(value: &LocketError) -> Self {
        value.exit_code()
    }
}

#[cfg(test)]
mod tests {
    use super::LocketError;

    const ALL_ERRORS: &[LocketError] = &[
        LocketError::InvalidReference,
        LocketError::GitWorktreeRequired,
        LocketError::InvalidSecretName,
        LocketError::InvalidProfileName,
        LocketError::PolicyValidationIncomplete,
        LocketError::InvalidPolicy,
        LocketError::PolicyNotFound,
        LocketError::EnvironmentConflict,
        LocketError::MetadataInvalid,
        LocketError::MetadataLooksLikeSecret,
        LocketError::ConfirmationFailed,
        LocketError::TtyRequired,
        LocketError::ScanFindingBlocked,
        LocketError::SecretAlreadyExists,
        LocketError::AccessDenied,
        LocketError::DangerousProfileConfirmationRequired,
        LocketError::TeamRoleDenied,
        LocketError::ProjectRootUntrusted,
        LocketError::ProjectNotFound,
        LocketError::UnlockRequired,
        LocketError::GrantRequired,
        LocketError::UserVerificationFailed,
        LocketError::SecretVersionExpired,
        LocketError::SecretDeleted,
        LocketError::SecretNotFound,
        LocketError::ProfileNotFound,
        LocketError::AgentUnavailable,
        LocketError::AgentSocketInUse,
        LocketError::AutomationClientNotTrusted,
        LocketError::AutomationClientReplayDetected,
        LocketError::ExternalSourceUnavailable,
        LocketError::IdeEnvSessionUnavailable,
        LocketError::UpdateManifestInvalid,
        LocketError::SecretVersionOverflow,
        LocketError::CorruptDb,
        LocketError::StorageBusy,
        LocketError::SchemaNewerThanBinary,
        LocketError::AuditIntegrityFailed,
        LocketError::KeychainUnavailable,
        LocketError::LostRecoveryCode,
        LocketError::LostKeychainEntry,
        LocketError::UnrecoverableVault,
        LocketError::BundleVerificationFailed,
        LocketError::InviteExpired,
        LocketError::TeamBundleConflict,
        LocketError::DeviceRevoked,
        LocketError::ReplayDetected,
        LocketError::DeviceDescriptorInvalid,
        LocketError::InviteSignatureInvalid,
    ];

    #[test]
    fn maps_input_exit_codes() {
        assert_eq!(LocketError::InvalidReference.exit_code(), 64);
        assert_eq!(LocketError::GitWorktreeRequired.exit_code(), 64);
        assert_eq!(LocketError::InvalidSecretName.exit_code(), 64);
        assert_eq!(LocketError::InvalidProfileName.exit_code(), 64);
        assert_eq!(LocketError::PolicyNotFound.exit_code(), 64);
        assert_eq!(LocketError::ProjectNotFound.exit_code(), 64);
        assert_eq!(LocketError::PolicyValidationIncomplete.exit_code(), 65);
        assert_eq!(LocketError::InvalidPolicy.exit_code(), 65);
        assert_eq!(LocketError::EnvironmentConflict.exit_code(), 66);
        assert_eq!(LocketError::MetadataInvalid.exit_code(), 64);
        assert_eq!(LocketError::MetadataLooksLikeSecret.exit_code(), 66);
        assert_eq!(LocketError::SecretAlreadyExists.exit_code(), 67);
        assert_eq!(LocketError::ConfirmationFailed.exit_code(), 68);
        assert_eq!(LocketError::TtyRequired.exit_code(), 68);
        assert_eq!(LocketError::ScanFindingBlocked.exit_code(), 69);
    }

    #[test]
    fn maps_authorization_exit_codes() {
        assert_eq!(LocketError::AccessDenied.exit_code(), 70);
        assert_eq!(LocketError::DangerousProfileConfirmationRequired.exit_code(), 70);
        assert_eq!(LocketError::TeamRoleDenied.exit_code(), 70);
        assert_eq!(LocketError::ProjectRootUntrusted.exit_code(), 71);
        assert_eq!(LocketError::UnlockRequired.exit_code(), 72);
        assert_eq!(LocketError::GrantRequired.exit_code(), 73);
        assert_eq!(LocketError::UserVerificationFailed.exit_code(), 74);
        assert_eq!(LocketError::SecretVersionExpired.exit_code(), 75);
        assert_eq!(LocketError::SecretDeleted.exit_code(), 76);
        assert_eq!(LocketError::SecretNotFound.exit_code(), 77);
        assert_eq!(LocketError::ProfileNotFound.exit_code(), 78);
    }

    #[test]
    fn maps_storage_and_later_exit_codes_below_reserved_shell_codes() {
        let cases = [
            (LocketError::AgentUnavailable, 80),
            (LocketError::AgentSocketInUse, 81),
            (LocketError::AutomationClientNotTrusted, 82),
            (LocketError::AutomationClientReplayDetected, 83),
            (LocketError::ExternalSourceUnavailable, 89),
            (LocketError::IdeEnvSessionUnavailable, 80),
            (LocketError::UpdateManifestInvalid, 89),
            (LocketError::SecretVersionOverflow, 90),
            (LocketError::CorruptDb, 90),
            (LocketError::StorageBusy, 91),
            (LocketError::SchemaNewerThanBinary, 92),
            (LocketError::AuditIntegrityFailed, 93),
            (LocketError::KeychainUnavailable, 100),
            (LocketError::LostRecoveryCode, 101),
            (LocketError::LostKeychainEntry, 102),
            (LocketError::UnrecoverableVault, 103),
            (LocketError::BundleVerificationFailed, 110),
            (LocketError::InviteExpired, 111),
            (LocketError::TeamBundleConflict, 112),
            (LocketError::DeviceRevoked, 113),
            (LocketError::ReplayDetected, 113),
            (LocketError::DeviceDescriptorInvalid, 113),
            (LocketError::InviteSignatureInvalid, 114),
            (LocketError::TtyRequired, 68),
        ];

        for (error, code) in cases {
            assert_eq!(error.exit_code(), code);
            assert!(error.exit_code() < 126);
        }
    }

    #[test]
    fn converts_error_references_to_exit_codes() {
        assert_eq!(super::ExitCode::from(&LocketError::GrantRequired), 73);
    }

    #[test]
    fn display_copy_covers_every_typed_error_without_secret_examples() {
        for error in ALL_ERRORS {
            assert_eq!(LocketError::from_code_name(&format!("{error:?}")), Some(*error));
            let copy = error.display_copy();
            assert!(!copy.reason.is_empty(), "{error:?} must have a reason");
            assert!(!copy.next_action.is_empty(), "{error:?} must have a next action");
            let rendered = format!("{} {}", copy.reason, copy.next_action);
            assert!(!rendered.contains("DATABASE_URL"));
            assert!(!rendered.contains("postgres://"));
        }
    }

    #[test]
    fn ide_env_session_unavailable_uses_agent_unavailable_band() {
        // errors.md row 32 ("Agent unavailable | ... fail closed | 80") covers
        // the IDE env-session failure: the agent cannot serve the session map.
        assert_eq!(LocketError::IdeEnvSessionUnavailable.exit_code(), 80);
        assert_eq!(
            LocketError::IdeEnvSessionUnavailable.exit_code(),
            LocketError::AgentUnavailable.exit_code(),
        );
        assert_eq!(
            LocketError::from_code_name("IdeEnvSessionUnavailable"),
            Some(LocketError::IdeEnvSessionUnavailable),
        );
        assert_eq!(
            LocketError::IdeEnvSessionUnavailable.to_string(),
            "ide env session unavailable"
        );
    }

    #[test]
    fn code_names_round_trip_for_agent_error_envelopes() {
        assert_eq!(
            LocketError::from_code_name("AgentUnavailable"),
            Some(LocketError::AgentUnavailable)
        );
        assert_eq!(
            LocketError::from_code_name("UnlockRequired"),
            Some(LocketError::UnlockRequired)
        );
        assert_eq!(LocketError::from_code_name("GrantRequired"), Some(LocketError::GrantRequired));
        assert_eq!(
            LocketError::from_code_name("DangerousProfileConfirmationRequired"),
            Some(LocketError::DangerousProfileConfirmationRequired)
        );
        assert_eq!(LocketError::from_code_name("ProtocolError"), None);
    }

    #[test]
    fn displays_stable_error_messages() {
        let cases = [
            (LocketError::InvalidReference, "invalid locket reference"),
            (LocketError::EnvironmentConflict, "environment conflict"),
            (LocketError::MetadataInvalid, "metadata invalid"),
            (LocketError::MetadataLooksLikeSecret, "metadata looks like secret"),
            (LocketError::SecretAlreadyExists, "secret already exists"),
            (LocketError::UnrecoverableVault, "vault unrecoverable"),
            (LocketError::DeviceRevoked, "device revoked"),
            (LocketError::ReplayDetected, "invite replay detected"),
            (LocketError::DeviceDescriptorInvalid, "device descriptor invalid"),
            (LocketError::InviteSignatureInvalid, "invite signature invalid"),
            (LocketError::ConfirmationFailed, "confirmation did not match"),
            (LocketError::TtyRequired, "interactive TTY required"),
            (LocketError::SecretNotFound, "secret not found"),
            (LocketError::ProfileNotFound, "profile not found"),
            (LocketError::SecretVersionOverflow, "secret version overflow"),
            (LocketError::ProjectNotFound, "project not found"),
            (LocketError::InvalidSecretName, "invalid secret name"),
            (LocketError::InvalidProfileName, "invalid profile name"),
        ];

        for (error, message) in cases {
            assert_eq!(error.to_string(), message);
        }
    }
}
