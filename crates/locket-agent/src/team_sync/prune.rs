use std::collections::BTreeSet;

use locket_crypto::KeyBytes;
use locket_store::Store;
use rusqlite::{Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::{Result, reject, snapshot::local_owner, transport};

/// Counts recorded remote packages and lists deletions or dry-run candidates.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct PruneResult {
    pub dry_run: bool,
    pub keep_epochs: usize,
    pub examined: usize,
    pub deleted: usize,
    pub kept: usize,
    pub deleted_filenames: Vec<String>,
}

fn active_recipients(store: &Store, project: &str) -> Result<BTreeSet<String>> {
    let mut statement = store.connection().prepare(
        "SELECT d.fingerprint FROM devices d
         JOIN team_members m ON m.device_id = d.id
         JOIN teams t ON t.id = m.team_id
         WHERE t.project_id = ?1 AND d.revoked_at IS NULL AND m.removed_at IS NULL",
    )?;
    let rows = statement.query_map([project], |row| row.get::<_, String>(0))?;
    rows.collect::<std::result::Result<BTreeSet<_>, _>>().map_err(Into::into)
}

/// Let the pinned owner prune recorded remote packages. Retain the newest
/// delivered epochs for active recipients and none for removed or revoked recipients.
/// # Errors
/// Rejects unauthorized devices, zero retention, and storage or transport failures.
pub fn prune_remote_packages(
    store: &Store,
    project: &str,
    master: Option<&KeyBytes>,
    keep_epochs: usize,
    dry_run: bool,
) -> Result<PruneResult> {
    let owner = local_owner(store, project)?;
    if keep_epochs == 0 {
        return Err(reject("keep_epochs must be at least 1"));
    }
    let (transport, configured) = transport::open_configured(store, project, master)?;
    let remote_names = transport.list_packages()?;
    let active = active_recipients(store, project)?;
    let mut result = PruneResult { dry_run, keep_epochs, ..PruneResult::default() };
    let mut candidates = Vec::new();
    {
        // Outbox rows follow epoch order per recipient, even with legacy names.
        // Upload retries can change a filename without changing its row ID.
        let mut statement = store.connection().prepare(
            "SELECT rowid, filename, recipient, delivered FROM team_sync_outbox
             WHERE project_id=?1 ORDER BY recipient, rowid DESC",
        )?;
        let mut rows = statement.query([project])?;
        let mut recipient = String::new();
        let mut retained_epochs = 0;
        while let Some(row) = rows.next()? {
            let filename: String = row.get(1)?;
            let listed = remote_names.binary_search(&filename).is_ok();
            if listed {
                result.examined += 1;
            }
            let row_recipient: String = row.get(2)?;
            if row_recipient != recipient {
                recipient = row_recipient;
                retained_epochs = 0;
            }
            let delivered: bool = row.get(3)?;
            if !active.contains(&recipient) {
                // Delete these packages even if a prior upload never marked them delivered.
                if listed {
                    candidates.push((
                        row.get::<_, i64>(0)?,
                        filename,
                        recipient.clone(),
                        false,
                        true,
                    ));
                }
            } else if delivered && retained_epochs == keep_epochs {
                // A lost DELETE response can leave an obsolete outbox row after
                // its object disappears. Retry the deletion before retiring it.
                if listed || !dry_run {
                    candidates.push((
                        row.get::<_, i64>(0)?,
                        filename,
                        recipient.clone(),
                        true,
                        listed,
                    ));
                }
            } else if listed {
                result.kept += 1;
                retained_epochs += usize::from(delivered);
            }
        }
    }

    for (rowid, filename, recipient, require_delivered, listed) in candidates {
        if !dry_run {
            let tx =
                Transaction::new_unchecked(store.connection(), TransactionBehavior::Immediate)?;
            if local_owner(store, project)? != owner
                || transport::configured(store, project)?
                    .is_none_or(|current| current.config != configured.config)
            {
                return Err(reject("team owner or transport changed during prune; retry"));
            }
            let still_eligible: bool = if require_delivered {
                tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM team_sync_outbox
                     WHERE project_id=?1 AND rowid=?2 AND filename=?3 AND delivered=1)",
                    (project, rowid, &filename),
                    |row| row.get(0),
                )?
            } else {
                let row_exists: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM team_sync_outbox
                     WHERE project_id=?1 AND rowid=?2 AND filename=?3 AND recipient=?4)",
                    (project, rowid, &filename, &recipient),
                    |row| row.get(0),
                )?;
                let still_active: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices d
                     JOIN team_members m ON m.device_id = d.id
                     JOIN teams t ON t.id = m.team_id
                     WHERE t.project_id=?1 AND d.fingerprint=?2
                       AND d.revoked_at IS NULL AND m.removed_at IS NULL)",
                    (project, &recipient),
                    |row| row.get(0),
                )?;
                row_exists && !still_active
            };
            if !still_eligible {
                continue;
            }
            transport.delete_package(&filename)?;
            tx.execute("DELETE FROM team_sync_outbox WHERE rowid=?1", [rowid])?;
            tx.commit()?;
        }
        // Some backends acknowledge an absent object as a successful deletion.
        if listed {
            result.deleted_filenames.push(filename);
        }
    }
    result.deleted = result.deleted_filenames.len();
    Ok(result)
}
