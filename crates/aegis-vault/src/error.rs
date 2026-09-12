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
    /// The credential store was reached successfully, but holds no VMK
    /// for this vault's credential-store identity. This is a
    /// well-formed "nothing stored here" answer, *not* a broken store:
    /// distinguishing the two matters because a missing VMK for an
    /// existing database means that database's contents are
    /// permanently unrecoverable (profile reset, keychain wipe,
    /// machine migration), while
    /// `HardwareKeyStoreUnavailable` is potentially transient.
    VmkMissing,
    /// The credential store already holds a VMK at this vault's
    /// credential-store identity, but no database file exists at
    /// `db_path`. Creating a vault here would overwrite that VMK and
    /// irrecoverably destroy whatever it protects, so `Vault::open`
    /// refuses instead. The caller must resolve the collision
    /// explicitly (point at the right path, or destroy the stale
    /// credential first).
    VmkAlreadyExists,
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
            VaultError::VmkMissing => {
                write!(
                    f,
                    "no vault master key found in the credential store for this vault"
                )
            }
            VaultError::VmkAlreadyExists => {
                write!(
                    f,
                    "a vault master key already exists in the credential store for this vault, \
                     but no database file exists at its path; refusing to overwrite it"
                )
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

    /// `VmkMissing` must read as "nothing is stored", never as "the
    /// store is broken" — the whole point of splitting it out of
    /// `HardwareKeyStoreUnavailable` is that a user seeing this
    /// message must not be led into "retry / reboot" thinking.
    #[test]
    fn vmk_missing_display_says_not_found_not_unavailable() {
        let message = VaultError::VmkMissing.to_string();
        assert!(
            message.contains("no vault master key found"),
            "expected a 'not found' message, got: {message}"
        );
        assert!(
            !message.contains("unavailable"),
            "VmkMissing must not read as an unavailable store, got: {message}"
        );
    }

    #[test]
    fn vmk_already_exists_display_explains_the_refusal() {
        let message = VaultError::VmkAlreadyExists.to_string();
        assert!(
            message.contains("already exists"),
            "expected an 'already exists' message, got: {message}"
        );
        assert!(
            message.contains("refusing to overwrite"),
            "expected the message to state the refusal, got: {message}"
        );
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
