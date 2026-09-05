//! Crate-wide error type for `aegis-crypto`.
//!
//! Every fallible operation in this crate that can be driven by
//! attacker-controlled bytes (peer public keys, KEM encapsulation keys,
//! KEM ciphertexts) returns [`CryptoError`] rather than panicking. In a
//! messenger, a panic reachable from wire data is a remote
//! denial-of-service: one malformed byte string from any peer would
//! abort the process. See `AEGIS.Plan.V0.2.md` Section 2 and the
//! project rule against `unwrap()`/`expect()` in production paths.
//!
//! The deliberate exceptions are OS-RNG failures (`getrandom::fill`),
//! which stay as fail-closed `expect()` panics: they are not
//! attacker-controlled, and continuing without entropy would silently
//! produce predictable keys. Each such site documents the reasoning in
//! its own doc comment.
//!
//! One crate-wide enum (rather than per-module enums) is deliberate:
//! four downstream crates (`aegis-ratchet`, `aegis-vault`,
//! `aegis-file`, `aegis-net`) will propagate these with `?` across
//! module boundaries, and a single type keeps that free of conversion
//! boilerplate. The enum is `#[non_exhaustive]` so variants can be
//! added later without a breaking change for those crates.

use core::fmt;

/// Errors returned by `aegis-crypto`'s fallible primitives.
///
/// Variants carry only length/shape information that the peer already
/// knows (it supplied the bytes) — never secret-dependent detail, so
/// rendering or logging an error cannot leak key material. In
/// particular there is no variant distinguishing "valid ciphertext for
/// the wrong key" from "valid ciphertext for the right key": ML-KEM's
/// implicit rejection handles that internally and never surfaces here.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The peer's brainpoolP512r1 public key was not a valid SEC1 point
    /// encoding (wrong length, not on the curve, or the identity).
    InvalidPeerPublicKey,

    /// The supplied ML-KEM-1024 encapsulation key was not the expected
    /// number of bytes.
    InvalidEncapsulationKeyLength {
        /// Byte length ML-KEM-1024 encapsulation keys always have.
        expected: usize,
        /// Byte length actually supplied.
        actual: usize,
    },

    /// The supplied ML-KEM-1024 encapsulation key was the right length
    /// but failed the crate's validity check (FIPS 203 modulus check).
    InvalidEncapsulationKey,

    /// The supplied ML-KEM-1024 ciphertext was not the expected number
    /// of bytes.
    InvalidCiphertextLength {
        /// Byte length ML-KEM-1024 ciphertexts always have.
        expected: usize,
        /// Byte length actually supplied.
        actual: usize,
    },

    /// More output was requested from one HKDF-SHA512 expansion than
    /// RFC 5869 permits (255 × HashLen bytes).
    KdfOutputLength {
        /// Number of output bytes requested.
        requested: usize,
    },

    /// A length-prefixed field of the KDF `info` string exceeded the
    /// range of its `u16` big-endian length prefix.
    KdfFieldTooLong {
        /// Which `info` field was too long.
        field: &'static str,
        /// Byte length actually supplied.
        len: usize,
    },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPeerPublicKey => {
                f.write_str("peer brainpoolP512r1 public key is not a valid SEC1 point encoding")
            }
            Self::InvalidEncapsulationKeyLength { expected, actual } => write!(
                f,
                "ML-KEM-1024 encapsulation key must be {expected} bytes, got {actual}"
            ),
            Self::InvalidEncapsulationKey => {
                f.write_str("ML-KEM-1024 encapsulation key failed validity checking")
            }
            Self::InvalidCiphertextLength { expected, actual } => write!(
                f,
                "ML-KEM-1024 ciphertext must be {expected} bytes, got {actual}"
            ),
            Self::KdfOutputLength { requested } => write!(
                f,
                "HKDF-SHA512 cannot expand to {requested} bytes in one call"
            ),
            Self::KdfFieldTooLong { field, len } => write!(
                f,
                "KDF info field `{field}` is {len} bytes, which exceeds its u16 length prefix"
            ),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<hkdf::InvalidLength> for CryptoError {
    fn from(_: hkdf::InvalidLength) -> Self {
        // `hkdf::InvalidLength` carries no detail; the only way to
        // provoke it is an over-long requested output, so the requested
        // length is filled in by the caller that has it. This impl
        // exists for the degenerate case where it isn't available.
        Self::KdfOutputLength { requested: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoError;

    #[test]
    fn display_names_the_offending_lengths() {
        let err = CryptoError::InvalidCiphertextLength {
            expected: 1568,
            actual: 3,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("1568"), "{rendered}");
        assert!(rendered.contains('3'), "{rendered}");
    }

    #[test]
    fn errors_are_comparable_so_callers_can_match_on_them() {
        assert_eq!(
            CryptoError::InvalidPeerPublicKey,
            CryptoError::InvalidPeerPublicKey
        );
        assert_ne!(
            CryptoError::InvalidPeerPublicKey,
            CryptoError::InvalidEncapsulationKey
        );
    }

    #[test]
    fn implements_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&CryptoError::InvalidPeerPublicKey);
    }
}
