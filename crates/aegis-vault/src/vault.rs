//! The `Vault` public API: a generic, namespaced, encrypted key/value
//! store over SQLCipher with hardware-backed key isolation. See
//! design spec Sections 1-3.

use crate::db;
use crate::error::VaultError;
use crate::kdf::derive_dek_wrap_key;
use crate::keystore::{HardwareKeyStore, KeyringBackend};
use aegis_crypto::aead::{decrypt, encrypt, AeadAlgorithm};
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

    /// Encrypts `plaintext` under a fresh, random per-record DEK,
    /// wraps that DEK under a VMK-derived key, and upserts the
    /// `(namespace, key)` row. See design spec Section 1 for why the
    /// DEK is random and stored (not derived) — that's what makes
    /// `erase` (Task 8) a real cryptographic-shredding guarantee.
    pub fn put(&mut self, namespace: &str, key: &str, plaintext: &[u8]) -> Result<(), VaultError> {
        let mut dek = Zeroizing::new([0u8; 32]);
        getrandom::fill(dek.as_mut())
            .map_err(|_| VaultError::StorageCorrupted("OS RNG failure generating DEK".into()))?;

        let mut record_nonce = [0u8; 12];
        getrandom::fill(&mut record_nonce)
            .map_err(|_| VaultError::StorageCorrupted("OS RNG failure generating nonce".into()))?;
        let ciphertext = encrypt(
            AeadAlgorithm::Aes256Gcm,
            &dek,
            &record_nonce,
            b"",
            plaintext,
        )
        .map_err(|_| VaultError::StorageCorrupted("failed to seal record".into()))?;

        let mut dek_nonce = [0u8; 12];
        getrandom::fill(&mut dek_nonce)
            .map_err(|_| VaultError::StorageCorrupted("OS RNG failure generating DEK nonce".into()))?;
        let wrap_key = derive_dek_wrap_key(&self.vmk);
        let wrapped_dek = encrypt(
            AeadAlgorithm::Aes256Gcm,
            &wrap_key,
            &dek_nonce,
            b"",
            dek.as_slice(),
        )
        .map_err(|_| VaultError::StorageCorrupted("failed to wrap DEK".into()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        self.conn.execute(
            "INSERT INTO vault_records (namespace, key, wrapped_dek, dek_nonce, ciphertext, nonce, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
             ON CONFLICT (namespace, key) DO UPDATE SET
                wrapped_dek = excluded.wrapped_dek,
                dek_nonce   = excluded.dek_nonce,
                ciphertext  = excluded.ciphertext,
                nonce       = excluded.nonce,
                updated_at  = excluded.updated_at",
            rusqlite::params![
                namespace,
                key,
                wrapped_dek,
                dek_nonce.to_vec(),
                ciphertext,
                record_nonce.to_vec(),
                now,
            ],
        )?;

        Ok(())
    }

    /// Returns `Ok(None)` if `(namespace, key)` has no record, or has
    /// been `erase`d (Task 8) — from the caller's perspective those
    /// two cases are indistinguishable, which is the point.
    pub fn get(&self, namespace: &str, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        // `wrapped_dek`/`dek_nonce`: `Option` because `erase` (Task 8)
        // sets them `NULL` in place rather than deleting the row.
        // `ciphertext`/`nonce`: always present for any row that exists
        // at all (`NOT NULL` in the schema).
        type RawRecordRow = (Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>, Vec<u8>);
        let row: Option<RawRecordRow> = self
            .conn
            .query_row(
                "SELECT wrapped_dek, dek_nonce, ciphertext, nonce FROM vault_records
                 WHERE namespace = ?1 AND key = ?2",
                rusqlite::params![namespace, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .ok();

        let Some((Some(wrapped_dek), Some(dek_nonce), ciphertext, nonce)) = row else {
            return Ok(None);
        };

        let dek_nonce_arr: [u8; 12] = dek_nonce
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::StorageCorrupted("dek_nonce has wrong length".into()))?;
        let wrap_key = derive_dek_wrap_key(&self.vmk);
        let dek_bytes = decrypt(
            AeadAlgorithm::Aes256Gcm,
            &wrap_key,
            &dek_nonce_arr,
            b"",
            &wrapped_dek,
        )
        .map_err(|_| VaultError::StorageCorrupted("failed to unwrap DEK".into()))?;
        let dek: [u8; 32] = dek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::StorageCorrupted("unwrapped DEK has wrong length".into()))?;

        let nonce_arr: [u8; 12] = nonce
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::StorageCorrupted("nonce has wrong length".into()))?;
        let plaintext = decrypt(AeadAlgorithm::Aes256Gcm, &dek, &nonce_arr, b"", &ciphertext)
            .map_err(|_| VaultError::StorageCorrupted("failed to open record".into()))?;

        Ok(Some(Zeroizing::new(plaintext)))
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

    #[test]
    fn put_then_get_round_trips_plaintext() {
        let path = temp_db_path("put-get");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.put("messages", "msg-1", b"hello aegis").unwrap();
        let got = vault.get("messages", "msg-1").unwrap().unwrap();
        assert_eq!(&*got, b"hello aegis");

        // Windows keeps an exclusive file lock for as long as the
        // underlying SQLite handle is open, so it must be dropped
        // before the temp file can be removed below.
        drop(vault);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn get_of_missing_key_returns_none_not_error() {
        let path = temp_db_path("get-missing");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        assert!(vault.get("messages", "nope").unwrap().is_none());

        // Windows keeps an exclusive file lock for as long as the
        // underlying SQLite handle is open, so it must be dropped
        // before the temp file can be removed below.
        drop(vault);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn put_overwrites_an_existing_record_with_a_fresh_dek() {
        let path = temp_db_path("put-overwrite");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.put("contacts", "alice", b"v1").unwrap();
        vault.put("contacts", "alice", b"v2").unwrap();
        let got = vault.get("contacts", "alice").unwrap().unwrap();
        assert_eq!(&*got, b"v2");

        // Windows keeps an exclusive file lock for as long as the
        // underlying SQLite handle is open, so it must be dropped
        // before the temp file can be removed below.
        drop(vault);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn different_namespaces_do_not_collide() {
        let path = temp_db_path("namespaces");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.put("ns-a", "key", b"a-value").unwrap();
        vault.put("ns-b", "key", b"b-value").unwrap();
        assert_eq!(&*vault.get("ns-a", "key").unwrap().unwrap(), b"a-value");
        assert_eq!(&*vault.get("ns-b", "key").unwrap().unwrap(), b"b-value");

        // Windows keeps an exclusive file lock for as long as the
        // underlying SQLite handle is open, so it must be dropped
        // before the temp file can be removed below.
        drop(vault);
        std::fs::remove_file(&path).unwrap();
    }
}
