//! The hardware-backed key store abstraction. Phase 1 ships one real
//! implementation (`KeyringBackend`, Task 4) covering Windows
//! Credential Manager and Linux Secret Service/Keyutils. This trait
//! boundary exists so a future Android Keystore / Apple Secure
//! Enclave backend can be added without touching `Vault`'s logic.

use crate::db::hex_encode;
use crate::error::VaultError;
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

/// Zero-fallback boundary: the only way anything in this crate can
/// obtain or store a Vault Master Key.
pub(crate) trait HardwareKeyStore {
    fn store_vmk(&self, vmk: &[u8; 32]) -> Result<(), VaultError>;
    fn load_vmk(&self) -> Result<Zeroizing<[u8; 32]>, VaultError>;
    // No non-test caller until `destroy_vault` (Task 9) calls it.
    // Remove this `allow` once that lands.
    #[allow(dead_code)]
    fn destroy_vmk(&self) -> Result<(), VaultError>;
}

#[cfg(test)]
pub(crate) struct MockKeyStore {
    stored: std::sync::Mutex<Option<[u8; 32]>>,
    unavailable: bool,
}

#[cfg(test)]
impl MockKeyStore {
    pub(crate) fn new() -> Self {
        Self {
            stored: std::sync::Mutex::new(None),
            unavailable: false,
        }
    }

    /// A mock that simulates the OS credential store being
    /// unreachable — every operation returns
    /// `HardwareKeyStoreUnavailable`, exercising the zero-fallback
    /// path without needing a real broken OS store.
    pub(crate) fn unavailable() -> Self {
        Self {
            stored: std::sync::Mutex::new(None),
            unavailable: true,
        }
    }
}

#[cfg(test)]
impl HardwareKeyStore for MockKeyStore {
    fn store_vmk(&self, vmk: &[u8; 32]) -> Result<(), VaultError> {
        if self.unavailable {
            return Err(VaultError::HardwareKeyStoreUnavailable(
                "mock: simulated unavailable store".into(),
            ));
        }
        *self.stored.lock().unwrap() = Some(*vmk);
        Ok(())
    }

    fn load_vmk(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        if self.unavailable {
            return Err(VaultError::HardwareKeyStoreUnavailable(
                "mock: simulated unavailable store".into(),
            ));
        }
        // `VmkMissing`, not `StorageCorrupted`: this must mirror what
        // the real `KeyringBackend` returns when the OS credential
        // store has no entry, or mock-based tests would exercise a
        // behaviour the real backend never produces.
        self.stored
            .lock()
            .unwrap()
            .map(Zeroizing::new)
            .ok_or(VaultError::VmkMissing)
    }

    fn destroy_vmk(&self) -> Result<(), VaultError> {
        if self.unavailable {
            return Err(VaultError::HardwareKeyStoreUnavailable(
                "mock: simulated unavailable store".into(),
            ));
        }
        *self.stored.lock().unwrap() = None;
        Ok(())
    }
}

/// The real, OS-native `HardwareKeyStore`. `keyring`'s `v1` feature
/// (the crate's default) automatically selects Windows Credential
/// Manager on Windows and the Secret Service (via `zbus`) on *nix —
/// one implementation covers both platforms in Phase 1's scope.
pub(crate) struct KeyringBackend {
    service_name: String,
    username: String,
}

impl KeyringBackend {
    /// `db_path` participates in the credential-store identity: it
    /// selects the *username* half of the `(service_name, username)`
    /// pair, so two vaults sharing one `keyring_service_name` (the
    /// natural pattern — one constant, app-identifying service name
    /// with per-profile database paths) address different credential
    /// entries instead of silently overwriting each other's VMK.
    ///
    /// Fails if `db_path`'s parent directory cannot be canonicalized;
    /// that directory has to exist anyway for SQLite to create or open
    /// the database under it, so this rejects nothing that would have
    /// otherwise worked.
    pub(crate) fn new(
        service_name: impl Into<String>,
        db_path: &Path,
    ) -> Result<Self, VaultError> {
        Ok(Self {
            service_name: service_name.into(),
            username: vmk_username_for_path(db_path)?,
        })
    }

    fn entry(&self) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(&self.service_name, &self.username).map_err(map_keyring_error)
    }
}

/// Derives the credential-store username that holds the VMK for the
/// vault database at `db_path`.
///
/// Only the *parent directory* is canonicalized, never the full path:
/// `std::fs::canonicalize` errors when its target doesn't exist, and on
/// the vault-creation path the database file legitimately doesn't exist
/// yet. The parent directory, by contrast, must already exist for
/// SQLite to create the file at all. Joining the canonical parent with
/// the (uncanonicalized) file name means `.`, `..`, and symlinked
/// directory components all normalize to one identity, while each
/// distinct file in that directory still keys separately.
///
/// SHA-256 then hex: the resulting username is fixed-length and
/// contains no path separators or platform-reserved characters, so it
/// survives every credential store's attribute-length and
/// character-class limits regardless of how long or how exotic the
/// original path was. The digest is not a secret — it exists to
/// separate identities, not to hide the path.
pub(crate) fn vmk_username_for_path(db_path: &Path) -> Result<String, VaultError> {
    // `Path::parent` returns `Some("")` for a bare relative file name
    // like `vault.db` (meaning "the current directory") and `None` only
    // for a path that is purely a root/prefix — which can never name a
    // database file. The empty case is remapped to `.` so that
    // `canonicalize` resolves it against the current directory instead
    // of failing on an empty path.
    let parent = match db_path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
        Some(parent) => parent,
        None => {
            return Err(VaultError::StorageCorrupted(format!(
                "db_path has no parent directory: {}",
                db_path.display()
            )))
        }
    };
    let file_name = db_path.file_name().ok_or_else(|| {
        VaultError::StorageCorrupted(format!(
            "db_path has no file name: {}",
            db_path.display()
        ))
    })?;
    let canonical_parent = std::fs::canonicalize(parent)?;
    let normalized = canonical_parent.join(file_name);
    let digest = Sha256::digest(normalized.to_string_lossy().as_bytes());
    Ok(format!("vmk-{}", *hex_encode(&digest)))
}

impl HardwareKeyStore for KeyringBackend {
    fn store_vmk(&self, vmk: &[u8; 32]) -> Result<(), VaultError> {
        self.entry()?.set_secret(vmk).map_err(map_keyring_error)
    }

    fn load_vmk(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let secret = Zeroizing::new(self.entry()?.get_secret().map_err(map_keyring_error)?);
        let array: [u8; 32] = secret.as_slice().try_into().map_err(|_| {
            VaultError::StorageCorrupted(format!(
                "keyring VMK entry has wrong length: {} bytes, expected 32",
                secret.len()
            ))
        })?;
        Ok(Zeroizing::new(array))
    }

    fn destroy_vmk(&self) -> Result<(), VaultError> {
        self.entry()?.delete_credential().map_err(map_keyring_error)
    }
}

/// `keyring::Error` is `#[non_exhaustive]`.
///
/// `NoEntry` is the one variant that is *not* a failure of the store:
/// it means the store answered correctly that nothing has ever been
/// stored under this identity (or that it was deleted). Collapsing it
/// into `HardwareKeyStoreUnavailable` would tell a user whose
/// credential was genuinely wiped — profile reset, keychain wipe,
/// machine migration — that the problem is transient and worth
/// retrying, when in fact their vault is permanently unrecoverable. It
/// maps to `VaultError::VmkMissing` so callers (and `Vault::open`'s
/// create path) can tell the two apart.
///
/// `NoDefaultStore` and `NoStorageAccess` mean the platform credential
/// store itself couldn't be reached — the zero-fallback trigger.
/// Everything else is a store-level failure this crate can't recover
/// from either, so it's folded into the same variant with its detail
/// preserved.
fn map_keyring_error(err: keyring::Error) -> VaultError {
    match err {
        keyring::Error::NoEntry => VaultError::VmkMissing,
        keyring::Error::NoDefaultStore | keyring::Error::NoStorageAccess(_) => {
            VaultError::HardwareKeyStoreUnavailable(err.to_string())
        }
        other => VaultError::HardwareKeyStoreUnavailable(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_stored_vmk() {
        let store = MockKeyStore::new();
        let vmk = [0x77u8; 32];
        store.store_vmk(&vmk).unwrap();
        assert_eq!(*store.load_vmk().unwrap(), vmk);
    }

    #[test]
    fn destroy_makes_load_fail() {
        let store = MockKeyStore::new();
        store.store_vmk(&[0x11u8; 32]).unwrap();
        store.destroy_vmk().unwrap();
        assert!(store.load_vmk().is_err());
    }

    /// The mock must report "nothing stored" exactly the way the real
    /// `KeyringBackend` does (`keyring::Error::NoEntry` ->
    /// `VmkMissing`), otherwise every mock-based test of the
    /// create/open decision would be exercising a fiction.
    #[test]
    fn empty_mock_store_reports_vmk_missing() {
        let store = MockKeyStore::new();
        assert!(matches!(store.load_vmk(), Err(VaultError::VmkMissing)));
    }

    #[test]
    fn destroyed_mock_store_reports_vmk_missing() {
        let store = MockKeyStore::new();
        store.store_vmk(&[0x11u8; 32]).unwrap();
        store.destroy_vmk().unwrap();
        assert!(matches!(store.load_vmk(), Err(VaultError::VmkMissing)));
    }

    /// `NoEntry` ("the store answered: nothing is here") must never be
    /// confused with a store that couldn't be reached at all.
    #[test]
    fn no_entry_maps_to_vmk_missing_and_other_errors_map_to_unavailable() {
        assert!(matches!(
            map_keyring_error(keyring::Error::NoEntry),
            VaultError::VmkMissing
        ));
        assert!(matches!(
            map_keyring_error(keyring::Error::NoDefaultStore),
            VaultError::HardwareKeyStoreUnavailable(_)
        ));
        assert!(matches!(
            map_keyring_error(keyring::Error::Invalid(
                "service".into(),
                "simulated invalid parameter".into()
            )),
            VaultError::HardwareKeyStoreUnavailable(_)
        ));
        assert!(matches!(
            map_keyring_error(keyring::Error::BadStoreFormat(
                "simulated bad store format".into()
            )),
            VaultError::HardwareKeyStoreUnavailable(_)
        ));
    }

    /// The detail of a genuinely-unavailable store must survive the
    /// mapping, so an operator can tell *why* the store failed.
    #[test]
    fn unavailable_mapping_preserves_the_keyring_detail() {
        let mapped = map_keyring_error(keyring::Error::BadStoreFormat(
            "simulated bad store format".into(),
        ));
        let VaultError::HardwareKeyStoreUnavailable(detail) = mapped else {
            panic!("expected HardwareKeyStoreUnavailable, got: {mapped:?}");
        };
        assert!(
            detail.contains("simulated bad store format"),
            "expected the keyring detail to be preserved, got: {detail}"
        );
    }

    #[test]
    fn different_db_paths_derive_different_usernames() {
        let dir = std::env::temp_dir();
        let a = vmk_username_for_path(&dir.join("vault-a.db")).unwrap();
        let b = vmk_username_for_path(&dir.join("vault-b.db")).unwrap();
        assert_ne!(a, b, "distinct database files must key separately");
    }

    #[test]
    fn the_same_db_path_derives_a_stable_username() {
        let path = std::env::temp_dir().join("vault-stable.db");
        assert_eq!(
            vmk_username_for_path(&path).unwrap(),
            vmk_username_for_path(&path).unwrap()
        );
    }

    /// `.` and `..` components in the *directory* portion must
    /// normalize away, so a caller that spells the same file two
    /// different ways still reaches the same credential entry rather
    /// than minting a second one.
    #[test]
    fn dot_and_dotdot_spellings_of_one_path_derive_the_same_username() {
        let dir = std::env::temp_dir();
        let nested = dir.join(format!("aegis-vault-username-norm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&nested);
        std::fs::create_dir_all(&nested).unwrap();

        let plain = nested.join("vault.db");
        let with_dot = nested.join(".").join("vault.db");
        let nested_dir_name = nested.file_name().unwrap();
        let with_dotdot = nested
            .join("..")
            .join(nested_dir_name)
            .join("vault.db");

        let expected = vmk_username_for_path(&plain).unwrap();
        assert_eq!(vmk_username_for_path(&with_dot).unwrap(), expected);
        assert_eq!(vmk_username_for_path(&with_dotdot).unwrap(), expected);

        std::fs::remove_dir_all(&nested).unwrap();
    }

    /// The derived username has to be usable as a credential-store
    /// attribute on every platform: fixed length, no separators, no
    /// reserved characters.
    #[test]
    fn derived_username_is_fixed_length_hex_with_no_path_characters() {
        let username = vmk_username_for_path(&std::env::temp_dir().join("vault.db")).unwrap();
        assert_eq!(
            username.len(),
            "vmk-".len() + 64,
            "expected 'vmk-' plus a 64-char SHA-256 hex digest, got: {username}"
        );
        assert!(username.starts_with("vmk-"));
        assert!(
            username[4..].chars().all(|c| c.is_ascii_hexdigit()),
            "expected only hex digits after the prefix, got: {username}"
        );
    }

    /// A `db_path` whose parent directory doesn't exist cannot be
    /// canonicalized — and since SQLite could not create the database
    /// there either, failing here rejects nothing that would otherwise
    /// have worked.
    #[test]
    fn username_derivation_fails_when_the_parent_directory_is_missing() {
        let missing = std::env::temp_dir()
            .join(format!("aegis-vault-no-such-dir-{}", std::process::id()))
            .join("vault.db");
        assert!(!missing.parent().unwrap().exists());
        assert!(matches!(
            vmk_username_for_path(&missing),
            Err(VaultError::Io(_))
        ));
    }

    #[test]
    fn unavailable_store_fails_every_operation() {
        let store = MockKeyStore::unavailable();
        assert!(matches!(
            store.store_vmk(&[0u8; 32]),
            Err(VaultError::HardwareKeyStoreUnavailable(_))
        ));
        assert!(matches!(
            store.load_vmk(),
            Err(VaultError::HardwareKeyStoreUnavailable(_))
        ));
        assert!(matches!(
            store.destroy_vmk(),
            Err(VaultError::HardwareKeyStoreUnavailable(_))
        ));
    }
}

#[cfg(test)]
mod real_backend_tests {
    use super::*;

    /// Exercises the actual OS credential store. `#[ignore]` by
    /// default — a fresh CI container often has no Secret Service
    /// daemon running. Run explicitly: `cargo test -p aegis-vault
    /// real_backend_tests -- --ignored`.
    #[test]
    #[ignore]
    fn round_trips_through_the_real_os_store() {
        let db_path = std::env::temp_dir().join("aegis-vault-real-backend-test.db");
        let backend =
            KeyringBackend::new("aegis-vault-test-real-backend", &db_path).unwrap();
        let vmk = [0x99u8; 32];
        backend.store_vmk(&vmk).unwrap();
        assert_eq!(*backend.load_vmk().unwrap(), vmk);
        backend.destroy_vmk().unwrap();
        // After deletion the real store answers `NoEntry`, which must
        // surface as `VmkMissing` — not as an unavailable store.
        assert!(matches!(backend.load_vmk(), Err(VaultError::VmkMissing)));
    }

    /// Two vaults that share one `keyring_service_name` but live at
    /// different `db_path`s must occupy different credential entries.
    /// Before the per-path username derivation, the second
    /// `store_vmk` here would have silently overwritten the first
    /// vault's VMK and destroyed it irrecoverably.
    #[test]
    #[ignore]
    fn two_db_paths_under_one_service_name_do_not_clobber_each_other() {
        let service = "aegis-vault-test-real-backend-collision";
        let dir = std::env::temp_dir();
        let a = KeyringBackend::new(service, &dir.join("collision-a.db")).unwrap();
        let b = KeyringBackend::new(service, &dir.join("collision-b.db")).unwrap();

        let vmk_a = [0xAAu8; 32];
        let vmk_b = [0xBBu8; 32];
        a.store_vmk(&vmk_a).unwrap();
        b.store_vmk(&vmk_b).unwrap();

        assert_eq!(*a.load_vmk().unwrap(), vmk_a, "vault A's VMK was clobbered");
        assert_eq!(*b.load_vmk().unwrap(), vmk_b);

        a.destroy_vmk().unwrap();
        b.destroy_vmk().unwrap();
    }
}
