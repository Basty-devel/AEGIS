//! The hardware-backed key store abstraction. Phase 1 ships one real
//! implementation (`KeyringBackend`, Task 4) covering Windows
//! Credential Manager and Linux Secret Service/Keyutils. This trait
//! boundary exists so a future Android Keystore / Apple Secure
//! Enclave backend can be added without touching `Vault`'s logic.

use crate::error::VaultError;
use zeroize::Zeroizing;

/// Zero-fallback boundary: the only way anything in this crate can
/// obtain or store a Vault Master Key.
// Not yet implemented outside tests: `KeyringBackend` (Task 4) is the
// first real implementor. Remove this `allow` once it lands.
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
