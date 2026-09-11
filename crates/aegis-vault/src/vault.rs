//! The `Vault` public API: a generic, namespaced, encrypted key/value
//! store over SQLCipher with hardware-backed key isolation. See
//! design spec Sections 1-3.

use crate::db;
use crate::error::VaultError;
use crate::keystore::{HardwareKeyStore, KeyringBackend};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct VaultConfig {
    pub db_path: PathBuf,
    pub keyring_service_name: String,
}

// `conn`, `db_path`, and `keyring_service_name` have no reader within
// this task: `conn` is exercised indirectly (it must exist and be
// correctly keyed for the tests below to pass), and `db_path` /
// `keyring_service_name` are retained now specifically so Task 9's
// `destroy_vault` doesn't have to retrofit fields onto this struct
// later — see this task's brief, "Produces" line. Remove this `allow`
// once a later task adds a reader for each field.
#[allow(dead_code)]
pub struct Vault {
    pub(crate) conn: Connection,
    pub(crate) vmk: Zeroizing<[u8; 32]>,
    db_path: PathBuf,
    keyring_service_name: String,
}

impl Vault {
    /// Opens an existing vault at `config.db_path`, or creates one if
    /// no file exists there yet. Both paths go through
    /// `HardwareKeyStore` — if the OS credential store can't be
    /// reached, this returns `Err` and no vault is created or opened.
    pub fn open(config: VaultConfig) -> Result<Self, VaultError> {
        let store = KeyringBackend::new(config.keyring_service_name.clone());
        Self::open_with_store(&config.db_path, &store, config.keyring_service_name)
    }

    /// Test seam: identical to `open` but takes any `HardwareKeyStore`,
    /// so tests can pass `MockKeyStore` instead of talking to a real
    /// OS credential store. `keyring_service_name` is only ever read
    /// again by `destroy_vault` (Task 9) reconstructing a real
    /// `KeyringBackend` — `MockKeyStore`-based tests can pass any
    /// fixed string.
    pub(crate) fn open_with_store(
        db_path: &Path,
        store: &dyn HardwareKeyStore,
        keyring_service_name: String,
    ) -> Result<Self, VaultError> {
        let db_exists = db_path.exists();

        let vmk = if db_exists {
            store.load_vmk()?
        } else {
            let mut vmk = Zeroizing::new([0u8; 32]);
            getrandom::fill(vmk.as_mut()).map_err(|_| {
                VaultError::StorageCorrupted("OS RNG failure generating VMK".into())
            })?;
            store.store_vmk(&vmk)?;
            vmk
        };

        let conn = if db_exists {
            db::open_existing(db_path, &vmk)?
        } else {
            match db::create_new(db_path, &vmk) {
                Ok(conn) => conn,
                Err(err) => {
                    // `store_vmk` above already succeeded, so a VMK is
                    // now orphaned in the credential store, and
                    // `db::create_new` may have left a partial `.db`
                    // file behind. Both are best-effort cleanup: if
                    // either fails, that failure must not mask or
                    // replace the original `db::create_new` error
                    // returned below, and it must not stop the other
                    // cleanup step from being attempted. Without this,
                    // a retry would see the partial file, take the
                    // existing-vault branch, load the orphaned (but
                    // valid) VMK, and then fail forever against the
                    // still-malformed file.
                    let _ = store.destroy_vmk();
                    let _ = std::fs::remove_file(db_path);
                    return Err(err);
                }
            }
        };

        Ok(Vault {
            conn,
            vmk,
            db_path: db_path.to_path_buf(),
            keyring_service_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MockKeyStore;
    use std::env::temp_dir;

    fn temp_db_path(name: &str) -> PathBuf {
        temp_dir().join(format!("aegis-vault-test-{name}-{}.db", std::process::id()))
    }

    #[test]
    fn open_creates_a_new_vault_when_no_file_exists() {
        let path = temp_db_path("open-create");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();

        let vault =
            Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        assert_eq!(vault.vmk.len(), 32);
        // Windows keeps an exclusive file lock for as long as the
        // underlying SQLite handle is open, so it must be dropped
        // before the temp file can be removed below.
        drop(vault);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn open_reopens_an_existing_vault_with_the_same_vmk() {
        let path = temp_db_path("open-reopen");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();

        let first =
            Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        let first_vmk = *first.vmk;
        drop(first);

        let second =
            Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        assert_eq!(*second.vmk, first_vmk);
        // Windows keeps an exclusive file lock for as long as the
        // underlying SQLite handle is open, so it must be dropped
        // before the temp file can be removed below.
        drop(second);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn open_cleans_up_orphaned_vmk_when_create_new_fails_after_store_vmk_succeeds() {
        let store = MockKeyStore::new();

        // A path whose parent directory doesn't exist: `db_path.exists()`
        // is false (so this takes the new-vault branch and `store_vmk`
        // succeeds), but `db::create_new`'s `Connection::open` then fails
        // because SQLite can't create a file under a missing directory —
        // a deterministic way to fail `create_new` *after* the VMK is
        // already stored.
        let bad_path = temp_dir()
            .join(format!(
                "aegis-vault-test-no-such-dir-{}",
                std::process::id()
            ))
            .join("vault.db");
        assert!(
            !bad_path.parent().unwrap().exists(),
            "precondition: parent directory must not exist"
        );

        let result =
            Vault::open_with_store(&bad_path, &store, "aegis-vault-test".to_string());
        assert!(
            result.is_err(),
            "expected db::create_new to fail for a path with a missing parent directory"
        );

        // The orphaned VMK must have been cleaned up: load_vmk should
        // fail exactly as it would if nothing had ever been stored,
        // rather than returning the orphaned-but-valid key.
        let load_result = store.load_vmk();
        assert!(
            matches!(load_result, Err(VaultError::StorageCorrupted(_))),
            "expected no VMK to remain stored after cleanup, got: {load_result:?}"
        );

        // A retry with a valid path must succeed cleanly, proving the
        // failed attempt above left no stuck state behind.
        let good_path = temp_db_path("open-cleanup-retry");
        let _ = std::fs::remove_file(&good_path);
        let vault =
            Vault::open_with_store(&good_path, &store, "aegis-vault-test".to_string()).unwrap();
        // Windows keeps an exclusive file lock for as long as the
        // underlying SQLite handle is open, so it must be dropped
        // before the temp file can be removed below.
        drop(vault);
        std::fs::remove_file(&good_path).unwrap();
    }

    #[test]
    fn open_fails_when_hardware_store_is_unavailable() {
        let path = temp_db_path("open-unavailable");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::unavailable();

        let result =
            Vault::open_with_store(&path, &store, "aegis-vault-test".to_string());
        assert!(matches!(
            result,
            Err(VaultError::HardwareKeyStoreUnavailable(_))
        ));
        assert!(!path.exists(), "no database file should be left behind");
    }
}
