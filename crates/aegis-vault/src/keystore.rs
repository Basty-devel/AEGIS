//! The hardware-backed key store abstraction. Phase 1 ships one real
//! implementation (`KeyringBackend`, Task 4) covering Windows
//! Credential Manager and Linux Secret Service/Keyutils. This trait
//! boundary exists so a future Android Keystore / Apple Secure
//! Enclave backend can be added without touching `Vault`'s logic.

use crate::error::VaultError;
use zeroize::Zeroizing;

/// Zero-fallback boundary: the only way anything in this crate can
/// obtain or store a Vault Master Key.
// `KeyringBackend` (Task 4, below) is now a real, non-test
// implementor, but nothing in non-test code constructs it or calls
// through this trait yet — that lands with `Vault::open` in Task 6.
// Remove this `allow` once that wiring exists.
#[allow(dead_code)]
pub(crate) trait HardwareKeyStore {
    fn store_vmk(&self, vmk: &[u8; 32]) -> Result<(), VaultError>;
    fn load_vmk(&self) -> Result<Zeroizing<[u8; 32]>, VaultError>;
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
        self.stored
            .lock()
            .unwrap()
            .map(Zeroizing::new)
            .ok_or_else(|| VaultError::StorageCorrupted("mock: no VMK stored".into()))
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
// Not yet constructed outside tests until `Vault::open` (Task 6)
// wires it in. Remove this `allow` once that lands.
#[allow(dead_code)]
pub(crate) struct KeyringBackend {
    service_name: String,
}

#[allow(dead_code)]
impl KeyringBackend {
    pub(crate) fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(&self.service_name, "vmk").map_err(map_keyring_error)
    }
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

/// `keyring::Error` is `#[non_exhaustive]`; `NoDefaultStore` and
/// `NoStorageAccess` mean the platform credential store itself
/// couldn't be reached — the zero-fallback trigger. Everything else
/// is a store-level failure this crate can't recover from either, so
/// it's folded into the same variant with its detail preserved.
// Only reachable through `KeyringBackend`'s methods above, which are
// themselves unused in non-test code until Task 6. Remove this
// `allow` alongside the ones on `KeyringBackend`.
#[allow(dead_code)]
fn map_keyring_error(err: keyring::Error) -> VaultError {
    match err {
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
        let backend = KeyringBackend::new("aegis-vault-test-real-backend");
        let vmk = [0x99u8; 32];
        backend.store_vmk(&vmk).unwrap();
        assert_eq!(*backend.load_vmk().unwrap(), vmk);
        backend.destroy_vmk().unwrap();
        assert!(backend.load_vmk().is_err());
    }
}
