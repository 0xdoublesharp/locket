//! Typed metadata-only requests for explicit pending-profile reconciliation.

use serde::{Deserialize, Serialize};

use crate::TeamSyncRequest;

/// Explicit local operation for a verified pending incoming profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TeamSyncAction {
    /// Rename the colliding local profile while retaining its existing data.
    RenameProfile {
        /// Actual stored id of the local profile the user chose to rename.
        local_profile_id: String,
        /// New local profile name. Domain validation remains in the service.
        new_name: String,
    },
    /// Preserve a colliding local secret as an override before accepting team data.
    PreserveOverride {
        /// Actual stored id of the local secret the user chose to preserve.
        local_secret_id: String,
    },
}

/// Request for `TeamSyncReconcile`. The agent enforces its existing `TeamSync` grant.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TeamSyncReconcileRequest {
    /// Existing selected project, actual profile, store and process-bound grant.
    #[serde(flatten)]
    pub scope: TeamSyncRequest,
    /// Verified incoming profile id whose pending collision is being resolved.
    pub incoming_profile_id: String,
    /// Explicit user-selected metadata-only operation.
    pub action: TeamSyncAction,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reconciliation_actions_have_distinct_metadata_only_wire_shapes()
    -> Result<(), serde_json::Error> {
        let rename = TeamSyncAction::RenameProfile {
            local_profile_id: "local-profile".into(),
            new_name: "preserved-local".into(),
        };
        assert_eq!(
            serde_json::to_value(&rename)?,
            json!({"kind":"rename_profile","local_profile_id":"local-profile","new_name":"preserved-local"})
        );
        assert_eq!(
            serde_json::from_value::<TeamSyncAction>(serde_json::to_value(&rename)?)?,
            rename
        );
        let preserve = TeamSyncAction::PreserveOverride { local_secret_id: "local-secret".into() };
        assert_eq!(
            serde_json::to_value(&preserve)?,
            json!({"kind":"preserve_override","local_secret_id":"local-secret"})
        );
        assert!(
            serde_json::from_value::<TeamSyncAction>(
                json!({"kind":"preserve_override","local_secret_id":"id","value":"not-accepted"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<TeamSyncAction>(
                json!({"kind":"rename_profile","local_secret_id":"id"})
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn reconciliation_scope_is_flat_and_does_not_contain_values() -> Result<(), serde_json::Error> {
        let request = TeamSyncReconcileRequest {
            scope: TeamSyncRequest {
                project_id: "project".into(),
                store_path: None,
                profile_id: Some("actual-profile".into()),
                grant_id: Some("grant".into()),
                binding: Some(crate::GrantBinding::new(123, "start")),
            },
            incoming_profile_id: "incoming".into(),
            action: TeamSyncAction::PreserveOverride { local_secret_id: "local-secret".into() },
        };
        let encoded = serde_json::to_value(request)?;
        assert_eq!(encoded["project_id"], "project");
        assert_eq!(encoded["profile_id"], "actual-profile");
        assert_eq!(encoded["action"]["kind"], "preserve_override");
        assert!(encoded.get("scope").is_none());
        assert!(encoded.get("value").is_none());
        Ok(())
    }
    #[test]
    fn transport_configure_wire_keeps_legacy_folder_and_redacts_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::team_sync::{CredentialMode, TransportConfig};
        use crate::{AgentMethod, RequestEnvelope, TeamSyncConfigureRequest};

        let legacy: TeamSyncConfigureRequest =
            serde_json::from_value(json!({"project_id":"p","folder":"/share"}))?;
        assert_eq!(legacy.folder.as_deref(), Some(std::path::Path::new("/share")));
        assert!(legacy.transport.is_none());

        let payload = json!({
            "project_id": "p",
            "transport": {
                "kind": "s3", "bucket":"bucket", "region":"auto",
                "endpoint":"http://localhost:9000", "credential_mode":"vault",
                "access_key_id":"example-access-id","secret_access_key":"credential-to-redact",
                "session_token":"session-token-to-redact"
            }
        });
        let remote: TeamSyncConfigureRequest = serde_json::from_value(payload.clone())?;
        let envelope = RequestEnvelope::new("sync", AgentMethod::TeamSyncConfigure, payload);
        for debug in [format!("{remote:?}"), format!("{envelope:?}")] {
            for credential in
                ["example-access-id", "credential-to-redact", "session-token-to-redact"]
            {
                assert!(!debug.contains(credential));
            }
        }
        let (config, credentials) =
            remote.transport.ok_or("remote transport missing")?.into_parts()?;
        assert!(matches!(
            config,
            TransportConfig::S3 { path_style: true, credential_mode: CredentialMode::Vault, .. }
        ));
        assert!(credentials.is_some());
        assert_eq!(AgentMethod::TeamSyncTestRemote.as_str(), "team_sync.test_remote");
        assert_eq!(
            "team_sync.test_remote".parse::<AgentMethod>()?,
            AgentMethod::TeamSyncTestRemote
        );

        let webdav_payload = json!({
            "project_id": "p",
            "transport": {
                "kind": "webdav",
                "url": "http://127.0.0.1:8080/team",
                "credential_mode": "vault",
                "auth_kind": "bearer",
                "secret": "webdav-bearer-to-redact"
            }
        });
        let webdav_req: TeamSyncConfigureRequest = serde_json::from_value(webdav_payload)?;
        assert!(!format!("{webdav_req:?}").contains("webdav-bearer-to-redact"));
        let (webdav_cfg, webdav_creds) =
            webdav_req.transport.ok_or("webdav transport missing")?.into_parts()?;
        assert_eq!(serde_json::to_value(&webdav_cfg)?["kind"], "webdav");
        assert!(webdav_creds.is_some());
        let webdav_basic = json!({
            "project_id": "p",
            "transport": {
                "kind": "webdav",
                "url": "http://127.0.0.1:8080/team",
                "credential_mode": "vault",
                "auth_kind": "basic",
                "username": "webdav-user-to-encrypt",
                "secret": "webdav-password-to-redact"
            }
        });
        let webdav_basic_req: TeamSyncConfigureRequest = serde_json::from_value(webdav_basic)?;
        let basic_debug = format!("{webdav_basic_req:?}");
        assert!(!basic_debug.contains("webdav-user-to-encrypt"));
        assert!(!basic_debug.contains("webdav-password-to-redact"));
        let (basic_cfg, basic_creds) =
            webdav_basic_req.transport.ok_or("webdav basic missing")?.into_parts()?;
        assert!(matches!(basic_cfg, TransportConfig::WebDav { username: None, .. }));
        assert!(matches!(
            basic_creds,
            Some(crate::team_sync::TransportSecretInput::WebDav { username: Some(_), .. })
        ));
        Ok(())
    }
}

/// Transport configuration accepted by the team sync configure RPC.
///
/// This request may carry explicit vault credentials. Its debug output is redacted.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[allow(missing_docs)]
pub enum TeamSyncTransportConfigureInput {
    Folder {
        path: String,
    },
    S3 {
        bucket: String,
        region: String,
        #[serde(default)]
        prefix: String,
        #[serde(default)]
        endpoint: Option<String>,
        #[serde(default)]
        path_style: Option<bool>,
        credential_mode: crate::team_sync::CredentialMode,
        #[serde(default, with = "secret_option")]
        access_key_id: Option<zeroize::Zeroizing<String>>,
        #[serde(default, with = "secret_option")]
        secret_access_key: Option<zeroize::Zeroizing<String>>,
        #[serde(default, with = "secret_option")]
        session_token: Option<zeroize::Zeroizing<String>>,
    },
    #[serde(rename = "webdav")]
    WebDav {
        url: String,
        credential_mode: crate::team_sync::CredentialMode,
        #[serde(default)]
        auth_kind: Option<crate::team_sync::WebDavAuthKind>,
        #[serde(default, with = "secret_option")]
        username: Option<zeroize::Zeroizing<String>>,
        #[serde(default, with = "secret_option")]
        secret: Option<zeroize::Zeroizing<String>>,
    },
}

impl std::fmt::Debug for TeamSyncTransportConfigureInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TeamSyncTransportConfigureInput([redacted])")
    }
}

impl TeamSyncTransportConfigureInput {
    /// Separate persistable transport metadata from the credentials sent over local IPC.
    ///
    /// # Errors
    /// Rejects a partially specified pair of S3 credentials.
    pub fn into_parts(
        self,
    ) -> crate::team_sync::Result<(
        crate::team_sync::TransportConfig,
        Option<crate::team_sync::TransportSecretInput>,
    )> {
        use crate::team_sync::{
            CredentialMode, SyncError, TransportConfig, TransportSecretInput, WebDavAuthKind,
        };
        Ok(match self {
            Self::Folder { path } => (TransportConfig::Folder { path }, None),
            Self::S3 {
                bucket,
                region,
                prefix,
                endpoint,
                path_style,
                credential_mode,
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                let path_style = path_style.unwrap_or_else(|| endpoint.is_some());
                let credentials = match (access_key_id, secret_access_key, session_token) {
                    (None, None, None) => None,
                    (Some(mut id), Some(secret_access_key), session_token) => {
                        Some(TransportSecretInput::S3 {
                            access_key_id: std::mem::take(&mut *id),
                            secret_access_key,
                            session_token,
                        })
                    }
                    _ => return Err(SyncError::Rejected("incomplete S3 credentials".into())),
                };
                (
                    TransportConfig::S3 {
                        bucket,
                        region,
                        prefix,
                        endpoint,
                        path_style,
                        credential_mode,
                    },
                    credentials,
                )
            }
            Self::WebDav { url, credential_mode, auth_kind, username, secret } => {
                let auth_kind = auth_kind.unwrap_or_else(|| match credential_mode {
                    CredentialMode::None => WebDavAuthKind::None,
                    _ if username.is_some() => WebDavAuthKind::Basic,
                    _ => WebDavAuthKind::Bearer,
                });
                let (config_username, credentials) = if credential_mode == CredentialMode::Vault {
                    (
                        None,
                        secret.map(|secret| TransportSecretInput::WebDav {
                            username: username.map(|mut name| std::mem::take(&mut *name)),
                            secret,
                        }),
                    )
                } else {
                    (
                        username.map(|mut name| std::mem::take(&mut *name)),
                        secret
                            .map(|secret| TransportSecretInput::WebDav { username: None, secret }),
                    )
                };
                (
                    TransportConfig::WebDav {
                        url,
                        credential_mode,
                        auth_kind,
                        username: config_username,
                    },
                    credentials,
                )
            }
        })
    }
}

mod secret_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroizing;

    #[allow(clippy::ref_option)]
    pub(super) fn serialize<S: Serializer>(
        secret: &Option<Zeroizing<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        secret.as_ref().map(|secret| secret.as_str()).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Zeroizing<String>>, D::Error> {
        Option::<String>::deserialize(deserializer).map(|secret| secret.map(Zeroizing::new))
    }
}
