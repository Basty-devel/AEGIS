//! Crate-wide error type for `aegis-ratchet`.
//!
//! Wraps `aegis_crypto::CryptoError` for errors propagated from
//! primitive calls, plus this crate's own protocol-level failure
//! modes. Nothing that can be driven by attacker-controlled bytes
//! (peer bundles, wire messages, tampered ciphertext) may panic — see
//! this plan's Global Constraints and `AEGIS.Plan.V0.2.md` Section 2.

use core::fmt;

/// Errors returned by `aegis-ratchet`'s fallible operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RatchetError {
    /// Propagated from an `aegis-crypto` primitive call (malformed
    /// peer public key, KEM key/ciphertext, etc.).
    Crypto(aegis_crypto::CryptoError),
    /// A pre-key bundle's fields were the wrong length or otherwise
    /// structurally invalid.
    MalformedPreKeyBundle,
    /// A pre-key bundle's signed pre-key signature did not verify
    /// against its claimed identity key.
    InvalidBundleSignature,
    /// A wire message's fields were the wrong length or otherwise
    /// structurally invalid.
    MalformedMessage,
    /// A message's number is below the current receive counter and
    /// not found in the skipped-key cache — already processed, or its
    /// key was evicted past `SkippedKeyCache`'s bound.
    UnknownMessage,
    /// AEAD authentication failed (tampered ciphertext, wrong key).
    DecryptionFailed,
    /// A single ratchet step's skip gap exceeded `MAX_SKIP` (design
    /// §5) — deriving that many keys in one jump is refused rather
    /// than performed, to bound the cost of a single call.
    SkippedKeyLimitExceeded,
}

impl From<aegis_crypto::CryptoError> for RatchetError {
    fn from(err: aegis_crypto::CryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(err) => write!(f, "aegis-crypto error: {err}"),
            Self::MalformedPreKeyBundle => f.write_str("pre-key bundle is malformed"),
            Self::InvalidBundleSignature => {
                f.write_str("pre-key bundle's signed pre-key signature does not verify")
            }
            Self::MalformedMessage => f.write_str("ratchet message is malformed"),
            Self::UnknownMessage => {
                f.write_str("message key not found (already processed or evicted)")
            }
            Self::DecryptionFailed => f.write_str("AEAD decryption/authentication failed"),
            Self::SkippedKeyLimitExceeded => {
                f.write_str("skip gap exceeds the maximum skipped-key derivation limit")
            }
        }
    }
}

impl std::error::Error for RatchetError {}

#[cfg(test)]
mod tests {
    use super::RatchetError;

    #[test]
    fn crypto_error_converts_and_displays() {
        let crypto_err = aegis_crypto::CryptoError::InvalidPeerPublicKey;
        let err: RatchetError = crypto_err.clone().into();
        assert_eq!(err, RatchetError::Crypto(crypto_err));
        assert!(err.to_string().contains("brainpoolP512r1"));
    }

    #[test]
    fn errors_are_comparable() {
        assert_eq!(RatchetError::MalformedMessage, RatchetError::MalformedMessage);
        assert_ne!(RatchetError::MalformedMessage, RatchetError::UnknownMessage);
    }
}
