//! Passkey/WebAuthn credential records and `Store` operations.

use rusqlite::types::Type;
use rusqlite::{OptionalExtension, params};

use crate::Store;
use crate::error::StoreError;

/// Default `WebAuthn` relying party id for optional PRF credentials.
pub const DEFAULT_WEBAUTHN_RELYING_PARTY_ID: &str = "locket.localhost";

/// Stored passkey PRF wrap of the project master key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyPrfWrapRecord {
    /// Passkey credential metadata id this wrap belongs to.
    pub passkey_id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// PRF salt passed to the platform authenticator.
    pub prf_salt: Vec<u8>,
    /// AEAD ciphertext of the wrapped master key.
    pub wrapped_master_key: Vec<u8>,
    /// AEAD nonce used for the wrap.
    pub wrap_nonce: Vec<u8>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Passkey/WebAuthn credential public metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyCredentialRecord {
    /// Credential metadata identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Local device this credential is bound to.
    pub device_id: String,
    /// Team member this credential is bound to, when the project has a team.
    pub member_id: Option<String>,
    /// Human-readable authenticator label.
    pub label: String,
    /// Public `WebAuthn` credential id bytes. Never private key material.
    pub credential_id: Vec<u8>,
    /// Public key bytes for `WebAuthn` assertion verification.
    pub public_key: Vec<u8>,
    /// Stable random `WebAuthn` user handle. Never printed by default.
    pub user_handle: Vec<u8>,
    /// Transport hints exposed by the platform/authenticator.
    pub transports: Vec<String>,
    /// Whether PRF/hmac-secret key-wrapping is supported.
    pub prf_capable: bool,
    /// `WebAuthn` relying party id used when this credential was registered.
    pub webauthn_relying_party_id: String,
    /// Whether the authenticator reported backup eligibility.
    pub backup_eligible: Option<bool>,
    /// Whether the authenticator reported backup state.
    pub backup_state: Option<bool>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last-use timestamp in nanoseconds since the Unix epoch.
    pub last_used_at: Option<i64>,
    /// Revocation timestamp in nanoseconds since the Unix epoch.
    pub revoked_at: Option<i64>,
}

fn passkey_credential_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PasskeyCredentialRecord> {
    let transports_json = row.get::<_, String>(7)?;
    let transports = serde_json::from_str::<Vec<String>>(&transports_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, Type::Text, Box::new(error))
    })?;
    Ok(PasskeyCredentialRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        device_id: row.get(2)?,
        member_id: row.get(3)?,
        label: row.get(4)?,
        credential_id: row.get(5)?,
        public_key: row.get(6)?,
        transports,
        prf_capable: row.get(8)?,
        webauthn_relying_party_id: row.get(9)?,
        user_handle: row.get(10)?,
        backup_eligible: row.get(11)?,
        backup_state: row.get(12)?,
        created_at: row.get(13)?,
        last_used_at: row.get(14)?,
        revoked_at: row.get(15)?,
    })
}

impl Store {
    /// Inserts a passkey credential public metadata row.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert or
    /// [`StoreError::Json`] when transport metadata cannot be encoded.
    pub fn insert_passkey_credential(
        &self,
        credential: &PasskeyCredentialRecord,
    ) -> Result<(), StoreError> {
        let transports_json = serde_json::to_string(&credential.transports)?;
        self.connection.execute(
            "INSERT INTO passkey_credentials(
               id, project_id, device_id, member_id, label, credential_id, public_key,
               transports_json, prf_capable, webauthn_relying_party_id, user_handle,
               backup_eligible, backup_state, created_at, last_used_at, revoked_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                credential.id.as_str(),
                credential.project_id.as_str(),
                credential.device_id.as_str(),
                credential.member_id.as_deref(),
                credential.label.as_str(),
                credential.credential_id.as_slice(),
                credential.public_key.as_slice(),
                transports_json.as_str(),
                credential.prf_capable,
                credential.webauthn_relying_party_id.as_str(),
                credential.user_handle.as_slice(),
                credential.backup_eligible,
                credential.backup_state,
                credential.created_at,
                credential.last_used_at,
                credential.revoked_at,
            ],
        )?;

        Ok(())
    }

    /// Lists passkey credential metadata for a project ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query rows.
    pub fn list_passkey_credentials(
        &self,
        project_id: &str,
        include_revoked: bool,
    ) -> Result<Vec<PasskeyCredentialRecord>, StoreError> {
        let sql = if include_revoked {
            "SELECT id, project_id, device_id, member_id, label, credential_id, public_key,
                    transports_json, prf_capable, webauthn_relying_party_id, user_handle,
                    backup_eligible, backup_state, created_at, last_used_at, revoked_at
             FROM passkey_credentials
             WHERE project_id = ?1
             ORDER BY created_at, id"
        } else {
            "SELECT id, project_id, device_id, member_id, label, credential_id, public_key,
                    transports_json, prf_capable, webauthn_relying_party_id, user_handle,
                    backup_eligible, backup_state, created_at, last_used_at, revoked_at
             FROM passkey_credentials
             WHERE project_id = ?1 AND revoked_at IS NULL
             ORDER BY created_at, id"
        };
        let mut statement = self.connection.prepare(sql)?;
        let credentials = statement
            .query_map([project_id], passkey_credential_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(credentials)
    }

    /// Finds passkey credential metadata by label, id, or lowercase/uppercase credential-id hex prefix.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query rows.
    pub fn find_passkey_credentials(
        &self,
        project_id: &str,
        selector: &str,
    ) -> Result<Vec<PasskeyCredentialRecord>, StoreError> {
        let selector = selector.trim();
        let candidate = selector.strip_prefix("0x").unwrap_or(selector);
        let credential_hex_prefix = (!candidate.is_empty()
            && candidate.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| candidate.to_ascii_uppercase());
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, device_id, member_id, label, credential_id, public_key,
                    transports_json, prf_capable, webauthn_relying_party_id, user_handle,
                    backup_eligible, backup_state, created_at, last_used_at, revoked_at
             FROM passkey_credentials
             WHERE project_id = ?1
               AND (label = ?2 OR id = ?2 OR hex(credential_id) LIKE (?3 || '%'))
             ORDER BY revoked_at IS NULL DESC, created_at DESC, id",
        )?;
        let credentials = statement
            .query_map(
                params![project_id, selector, credential_hex_prefix],
                passkey_credential_from_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(credentials)
    }

    /// Inserts or replaces a passkey PRF wrap of the project master key.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert.
    pub fn upsert_passkey_prf_wrap(&self, wrap: &PasskeyPrfWrapRecord) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO passkey_prf_wraps(
               passkey_id, project_id, prf_salt, wrapped_master_key, wrap_nonce, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(passkey_id) DO UPDATE SET
               prf_salt = excluded.prf_salt,
               wrapped_master_key = excluded.wrapped_master_key,
               wrap_nonce = excluded.wrap_nonce,
               created_at = excluded.created_at",
            params![
                wrap.passkey_id.as_str(),
                wrap.project_id.as_str(),
                wrap.prf_salt.as_slice(),
                wrap.wrapped_master_key.as_slice(),
                wrap.wrap_nonce.as_slice(),
                wrap.created_at,
            ],
        )?;
        Ok(())
    }

    /// Returns the passkey PRF wrap for a given passkey credential id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query rows.
    pub fn get_passkey_prf_wrap(
        &self,
        project_id: &str,
        passkey_id: &str,
    ) -> Result<Option<PasskeyPrfWrapRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT passkey_id, project_id, prf_salt, wrapped_master_key, wrap_nonce, created_at
             FROM passkey_prf_wraps
             WHERE project_id = ?1 AND passkey_id = ?2",
        )?;
        let row = statement
            .query_row(params![project_id, passkey_id], |row| {
                Ok(PasskeyPrfWrapRecord {
                    passkey_id: row.get(0)?,
                    project_id: row.get(1)?,
                    prf_salt: row.get(2)?,
                    wrapped_master_key: row.get(3)?,
                    wrap_nonce: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    /// Lists active (non-revoked) passkey PRF wraps for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query rows.
    pub fn list_active_passkey_prf_wraps(
        &self,
        project_id: &str,
    ) -> Result<Vec<(PasskeyCredentialRecord, PasskeyPrfWrapRecord)>, StoreError> {
        let credentials = self.list_passkey_credentials(project_id, false)?;
        let mut pairs = Vec::new();
        for credential in credentials {
            if let Some(wrap) = self.get_passkey_prf_wrap(project_id, &credential.id)? {
                pairs.push((credential, wrap));
            }
        }
        Ok(pairs)
    }

    /// Marks a passkey credential revoked.
    ///
    /// Returns `true` when a row changed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn revoke_passkey_credential(
        &self,
        project_id: &str,
        credential_id: &str,
        revoked_at: i64,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "UPDATE passkey_credentials
             SET revoked_at = ?3
             WHERE project_id = ?1 AND id = ?2 AND revoked_at IS NULL",
            params![project_id, credential_id, revoked_at],
        )?;

        Ok(self.connection.changes() == 1)
    }
}
