//! Crate-wide error type for `aegis-net`.
//!
//! Every fallible operation that can be driven by attacker-controlled
//! bytes — a capability token presented by a peer or relay — returns
//! [`NetError`] rather than panicking, consistent with every other
//! crate in this workspace.

use core::fmt;

/// Errors returned by `aegis-net`'s capability-token and rate-limiting
/// engine.
///
/// Non-exhaustive: new failure modes may be added without a semver
/// break. Variants carry only length/timestamp/shape information a
/// peer already controls or could derive from the token it presented —
/// never secret-dependent detail.
#[derive(Debug)]
#[non_exhaustive]
pub enum NetError {
    /// A primitive-level cryptographic failure from `aegis-crypto`.
    Crypto(aegis_crypto::CryptoError),

    /// The token's dual signature (Ed25519 + ML-DSA-87) did not verify
    /// against its own claimed public keys and fields.
    SignatureInvalid,

    /// The token's validity window has ended.
    TokenExpired {
        /// The token's declared expiry, unix seconds.
        expires_at: u64,
        /// The time it was checked against, unix seconds.
        now: u64,
    },

    /// A validity window supplied to [`crate::capability::CapabilityToken::issue`]
    /// (or read back from a parsed token's own fields) is not sound —
    /// zero-length, exceeds
    /// [`crate::capability::MAX_TOKEN_VALIDITY_SECONDS`], or has
    /// `issued_at > expires_at`.
    InvalidValidityWindow {
        /// Why the window was rejected.
        reason: &'static str,
    },

    /// A [`crate::rate_limit::RateLimiter`] configuration is not sound
    /// (a zero-length window can never expire, so it would never reset
    /// and would deny every request forever after the first
    /// `max_requests` — almost certainly not the caller's intent, so
    /// this is rejected at construction rather than silently
    /// misbehaving).
    InvalidRateLimitConfig {
        /// Why the configuration was rejected.
        reason: &'static str,
    },

    /// A wire-encoded token ended before a fixed-size field could be
    /// read, or before a length-prefixed field's declared length could
    /// be satisfied.
    Truncated,

    /// Extra bytes remained after a complete, well-formed token was
    /// parsed.
    TrailingData,

    /// A length-prefixed field's declared length is internally
    /// inconsistent with the bytes actually available (used when the
    /// specific reason is "the prefix claims more than could possibly
    /// remain," distinguished from [`NetError::Truncated`] so callers
    /// can tell a merely-short buffer from an implausible/adversarial
    /// length claim).
    MalformedLength {
        /// Which field's length prefix was implausible.
        field: &'static str,
    },

    /// The wire encoding's fixed 4-byte magic did not match `b"CAP1"`.
    BadMagic,
}

impl From<aegis_crypto::CryptoError> for NetError {
    fn from(err: aegis_crypto::CryptoError) -> Self {
        NetError::Crypto(err)
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Crypto(err) => write!(f, "cryptographic error: {err}"),
            NetError::SignatureInvalid => f.write_str("capability token signature is invalid"),
            NetError::TokenExpired { expires_at, now } => write!(
                f,
                "capability token expired at {expires_at}, checked at {now}"
            ),
            NetError::InvalidValidityWindow { reason } => {
                write!(f, "invalid capability token validity window: {reason}")
            }
            NetError::InvalidRateLimitConfig { reason } => {
                write!(f, "invalid rate limiter configuration: {reason}")
            }
            NetError::Truncated => f.write_str("capability token bytes ended unexpectedly"),
            NetError::TrailingData => {
                f.write_str("extra bytes remained after a complete capability token")
            }
            NetError::MalformedLength { field } => {
                write!(f, "field `{field}` has an implausible length prefix")
            }
            NetError::BadMagic => {
                f.write_str("input is not an AegisPQC capability token (bad magic)")
            }
        }
    }
}

impl std::error::Error for NetError {}

#[cfg(test)]
mod tests {
    use super::NetError;

    #[test]
    fn display_names_the_offending_values() {
        let err = NetError::TokenExpired {
            expires_at: 1000,
            now: 2000,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("1000"), "{rendered}");
        assert!(rendered.contains("2000"), "{rendered}");
    }

    #[test]
    fn implements_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&NetError::BadMagic);
    }

    #[test]
    fn crypto_error_converts() {
        let crypto_err = aegis_crypto::CryptoError::InvalidPeerPublicKey;
        let net_err: NetError = crypto_err.into();
        assert!(matches!(net_err, NetError::Crypto(_)));
    }
}
