//! Atomic composition of store operations used by validated imports.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use crate::{Store, StoreError};

impl Store {
    /// Runs composed writes atomically, including nested lifecycle operations.
    ///
    /// A failed operation rolls back every write made by the closure. The
    /// savepoint also composes with an enclosing store transaction.
    ///
    /// # Errors
    ///
    /// Returns the operation error or a storage error if savepoint management fails.
    pub fn with_atomic_write<T, E>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<StoreError>,
    {
        self.connection.execute_batch("SAVEPOINT locket_atomic_write").map_err(StoreError::from)?;
        match catch_unwind(AssertUnwindSafe(|| operation(self))) {
            Ok(Ok(value)) => {
                if let Err(error) = self.connection.execute_batch("RELEASE locket_atomic_write") {
                    let _ = self.connection.execute_batch(
                        "ROLLBACK TO locket_atomic_write; RELEASE locket_atomic_write",
                    );
                    return Err(StoreError::from(error).into());
                }
                Ok(value)
            }
            Ok(Err(error)) => {
                self.connection
                    .execute_batch("ROLLBACK TO locket_atomic_write; RELEASE locket_atomic_write")
                    .map_err(StoreError::from)?;
                Err(error)
            }
            Err(payload) => {
                let _ = self
                    .connection
                    .execute_batch("ROLLBACK TO locket_atomic_write; RELEASE locket_atomic_write");
                resume_unwind(payload)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{StoreError, tests::*};

    #[test]
    fn atomic_write_rolls_back_prior_secret_when_a_later_write_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = open_initialized_store()?;
        insert_project_profile(&fixture.store)?;
        let result = fixture.store.with_atomic_write::<_, StoreError>(|store| {
            store.create_active_secret(
                &test_secret(),
                &test_secret_version(),
                &test_secret_blob(),
                &test_secret_fingerprint(),
            )?;
            store.create_active_secret(
                &test_secret(),
                &test_secret_version(),
                &test_secret_blob(),
                &test_secret_fingerprint(),
            )
        });
        assert!(result.is_err());
        assert!(
            fixture
                .store
                .get_secret_by_source("lk_proj_test", "lk_prof_test", "DATABASE_URL", "user-local")?
                .is_none()
        );
        assert!(fixture.store.connection().is_autocommit());
        Ok(())
    }

    #[test]
    fn atomic_write_rolls_back_if_a_deferred_constraint_rejects_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = open_initialized_store()?;
        let store = &mut fixture.store;
        insert_project_profile(store)?;
        store.connection().execute_batch("PRAGMA defer_foreign_keys = ON")?;
        let result = store.with_atomic_write::<_, StoreError>(|store| {
            store.insert_profile_if_absent("temporary", "lk_proj_test", "temporary", false, 300)?;
            store.insert_profile_if_absent("orphan", "absent", "orphan", false, 300)
        });
        assert!(matches!(
            result,
            Err(StoreError::Sqlite(error))
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation)
        ));
        assert!(store.get_profile_by_name("lk_proj_test", "temporary")?.is_none());
        assert!(store.get_profile_by_name("absent", "orphan")?.is_none());
        assert!(store.connection().is_autocommit());
        Ok(())
    }

    #[test]
    fn atomic_write_unwind_rolls_back_before_propagating_the_original_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = open_initialized_store()?;
        let store = &mut fixture.store;
        insert_project_profile(store)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.with_atomic_write::<(), StoreError>(|store| {
                store.insert_profile_if_absent(
                    "temporary",
                    "lk_proj_test",
                    "temporary",
                    false,
                    300,
                )?;
                std::panic::resume_unwind(Box::new("interrupted atomic write"));
            })
        }));
        assert_eq!(
            result.err().and_then(|payload| payload.downcast::<&str>().ok()).as_deref().copied(),
            Some("interrupted atomic write")
        );
        assert!(store.get_profile_by_name("lk_proj_test", "temporary")?.is_none());
        assert!(store.connection().is_autocommit());
        assert!(store.insert_profile_if_absent(
            "temporary",
            "lk_proj_test",
            "temporary",
            false,
            300
        )?);
        Ok(())
    }

    #[test]
    fn atomic_write_commits_composed_secret_lifecycle_operations()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = open_initialized_store()?;
        insert_project_profile(&fixture.store)?;
        fixture.store.with_atomic_write::<_, StoreError>(|store| {
            store.create_active_secret(
                &test_secret(),
                &test_secret_version(),
                &test_secret_blob(),
                &test_secret_fingerprint(),
            )
        })?;
        assert!(
            fixture
                .store
                .get_secret_by_source("lk_proj_test", "lk_prof_test", "DATABASE_URL", "user-local")?
                .is_some()
        );
        assert!(fixture.store.connection().is_autocommit());
        Ok(())
    }
}
