//! Unified error type for `aegis-core`.
//!
//! [`AegisError`] wraps every leaf-crate error variant so callers can use a
//! single error type across the entire AegisPQC stack.

use std::fmt;

/// Unified error for the AegisPQC runtime facade.
///
/// One variant per leaf crate, plus [`std::io::Error`] for I/O failures.
/// The enum is `#[non_exhaustive]` so new leaf crates can add variants
/// without a semver-breaking change.
#[derive(Debug)]
#[non_exhaustive]
pub enum AegisError {
    /// Error from [`aegis_crypto`].
    Crypto(aegis_crypto::CryptoError),
    /// Error from [`aegis_ratchet`].
    Ratchet(aegis_ratchet::RatchetError),
    /// Error from [`aegis_vault_pqc`].
    Vault(aegis_vault_pqc::VaultError),
    /// Error from [`aegis_file`].
    File(aegis_file::FileError),
    /// Error from [`aegis_net`].
    Net(aegis_net::NetError),
    /// Standard I/O error.
    Io(std::io::Error),
}

impl fmt::Display for AegisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::Ratchet(e) => write!(f, "ratchet: {e}"),
            Self::Vault(e) => write!(f, "vault: {e}"),
            Self::File(e) => write!(f, "file: {e}"),
            Self::Net(e) => write!(f, "net: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for AegisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            Self::Ratchet(e) => Some(e),
            Self::Vault(e) => Some(e),
            Self::File(e) => Some(e),
            Self::Net(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

impl From<aegis_crypto::CryptoError> for AegisError {
    fn from(e: aegis_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<aegis_ratchet::RatchetError> for AegisError {
    fn from(e: aegis_ratchet::RatchetError) -> Self {
        Self::Ratchet(e)
    }
}

impl From<aegis_vault_pqc::VaultError> for AegisError {
    fn from(e: aegis_vault_pqc::VaultError) -> Self {
        Self::Vault(e)
    }
}

impl From<aegis_file::FileError> for AegisError {
    fn from(e: aegis_file::FileError) -> Self {
        Self::File(e)
    }
}

impl From<aegis_net::NetError> for AegisError {
    fn from(e: aegis_net::NetError) -> Self {
        Self::Net(e)
    }
}

impl From<std::io::Error> for AegisError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_round_trips() {
        let msg = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let err = AegisError::Io(msg);
        let s = err.to_string();
        assert!(s.contains("io:"));
    }

    #[test]
    fn std_error_trait_implementation() {
        let msg = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let err = AegisError::Io(msg);
        let source = std::error::Error::source(&err);
        assert!(source.is_some());
    }
}
