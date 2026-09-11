//! Errors returned by `aegis-vault`'s fallible operations.

use std::fmt;

/// Errors returned by `aegis-vault`. Non-exhaustive: new failure modes
/// may be added without a semver break.
#[derive(Debug)]
#[non_exhaustive]
pub enum VaultError {
    /// The hardware-backed credential store (Windows Credential
    /// Manager / Linux Secret Service) could not be reached or
    /// initialized. This is the zero-fallback trigger — there is no
    /// other code path that can obtain or store a VMK.
    HardwareKeyStoreUnavailable(String),
    /// A VMK was loaded but failed to decrypt the stored canary —
    /// either the wrong key or a corrupted store.
    VmkCanaryMismatch,
    /// A stored record's bytes are malformed in a way that cannot be
    /// the product of this crate's own writes.
    StorageCorrupted(String),
    /// Underlying `rusqlite`/SQLCipher failure.
    Sqlite(rusqlite::Error),
    /// Underlying filesystem failure.
    Io(std::io::Error),
    /// A primitive-level cryptographic failure from `aegis-crypto`.
    Crypto(aegis_crypto::CryptoError),
}

impl From<aegis_crypto::CryptoError> for VaultError {
    fn from(err: aegis_crypto::CryptoError) -> Self {
        VaultError::Crypto(err)
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(err: rusqlite::Error) -> Self {
        VaultError::Sqlite(err)
    }
}

impl From<std::io::Error> for VaultError {
    fn from(err: std::io::Error) -> Self {
        VaultError::Io(err)
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::HardwareKeyStoreUnavailable(detail) => {
                write!(f, "hardware-backed key store unavailable: {detail}")
            }
            VaultError::VmkCanaryMismatch => {
                write!(f, "vault master key failed canary verification")
            }
            VaultError::StorageCorrupted(detail) => {
                write!(f, "vault storage corrupted: {detail}")
            }
            VaultError::Sqlite(err) => write!(f, "sqlite/sqlcipher error: {err}"),
            VaultError::Io(err) => write!(f, "filesystem error: {err}"),
            VaultError::Crypto(err) => write!(f, "cryptographic error: {err}"),
        }
    }
}

impl std::error::Error for VaultError {}

#[cfg(test)]
mod tests {
    use super::VaultError;

    #[test]
    fn display_names_the_failure_kind() {
        let err = VaultError::VmkCanaryMismatch;
        assert_eq!(
            err.to_string(),
            "vault master key failed canary verification"
        );
    }

    #[test]
    fn hardware_key_store_unavailable_includes_detail() {
        let err = VaultError::HardwareKeyStoreUnavailable("no Secret Service daemon".into());
        assert!(err.to_string().contains("no Secret Service daemon"));
    }

    #[test]
    fn implements_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<VaultError>();
    }

    #[test]
    fn crypto_error_converts() {
        let crypto_err = aegis_crypto::CryptoError::InvalidPeerPublicKey;
        let vault_err: VaultError = crypto_err.into();
        assert!(matches!(vault_err, VaultError::Crypto(_)));
    }
}
