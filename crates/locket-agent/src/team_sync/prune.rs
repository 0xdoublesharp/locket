use locket_crypto::KeyBytes;
use locket_store::Store;
use rusqlite::{Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::{Result, reject, snapshot::local_owner, transport};

/// Counts known remote packages and identifies those pruned or selected in a dry run.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct PruneResult {
    pub dry_run: bool,
    pub keep_epochs: usize,
    pub examined: usize,
    pub deleted: usize,
    pub kept: usize,
    pub deleted_filenames: Vec<String>,
}

/// Prune superseded, delivered packages for the pinned local owner.
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
    let mut result = PruneResult { dry_run, keep_epochs, ..PruneResult::default() };
    let mut candidates = Vec::new();
    {
        // Outbox inserts follow each recipient's epoch order, including legacy
        // filenames. Conflict retries update a row in place.
        let mut statement = store.connection().prepare(
            "SELECT rowid, filename, recipient, delivered FROM team_sync_outbox
             WHERE project_id=?1 ORDER BY recipient, rowid DESC",
        )?;
        let mut rows = statement.query([project])?;
        let mut recipient = String::new();
        let mut retained_epochs = 0;
        while let Some(row) = rows.next()? {
            let filename: String = row.get(1)?;
            if remote_names.binary_search(&filename).is_err() {
                continue;
            }
            result.examined += 1;
            let row_recipient: String = row.get(2)?;
            if row_recipient != recipient {
                recipient = row_recipient;
                retained_epochs = 0;
            }
            let delivered: bool = row.get(3)?;
            if delivered && retained_epochs == keep_epochs {
                candidates.push((row.get::<_, i64>(0)?, filename));
            } else {
                result.kept += 1;
                retained_epochs += usize::from(delivered);
            }
        }
    }

    for (rowid, filename) in candidates {
        if !dry_run {
            let tx =
                Transaction::new_unchecked(store.connection(), TransactionBehavior::Immediate)?;
            if local_owner(store, project)? != owner
                || transport::configured(store, project)?
                    .is_none_or(|current| current.config != configured.config)
            {
                return Err(reject("team owner or transport changed during prune; retry"));
            }
            let still_delivered: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM team_sync_outbox
                 WHERE project_id=?1 AND rowid=?2 AND filename=?3 AND delivered=1)",
                (project, rowid, &filename),
                |row| row.get(0),
            )?;
            if !still_delivered {
                continue;
            }
            transport.delete_package(&filename)?;
            tx.execute("DELETE FROM team_sync_outbox WHERE rowid=?1", [rowid])?;
            tx.commit()?;
        }
        result.deleted_filenames.push(filename);
    }
    result.deleted = result.deleted_filenames.len();
    Ok(result)
}
