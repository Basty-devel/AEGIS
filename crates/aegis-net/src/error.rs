//! Crate-wide error types for `aegis-net`.
//!
//! [`NetError`] covers the capability-token and rate-limiting engine
//! (Section 6.3); [`TransportError`] covers the `Transport` layer
//! (Section 6.1) — two independent tracks (see
//! `docs/superpowers/specs/2026-09-12-aegis-net-capability-tokens-design.md`
//! and `docs/superpowers/specs/2026-09-12-aegis-net-transport-phase1-design.md`).
//! Every fallible operation that can be driven by attacker-controlled
//! bytes or network conditions returns one of these rather than
//! panicking, consistent with every other crate in this workspace.

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

/// Errors from `aegis-net`'s `Transport` layer — dialing, hosting, and
/// operating a byte-stream connection over Tor (or, in tests, the
/// in-memory `FakeTransport`).
///
/// Non-exhaustive: new failure modes may be added without a semver
/// break. Variants are split by retryability, not merely by which
/// underlying call failed — see each variant's doc comment.
#[derive(Debug)]
#[non_exhaustive]
pub enum TransportError {
    /// The Tor client failed to bootstrap (e.g. consensus fetch or
    /// guard selection failed). Retrying identically is unlikely to
    /// help without investigating why.
    Bootstrap(String),

    /// Bootstrapping did not complete within the configured
    /// `TorTransportConfig::bootstrap_timeout`. Distinct from
    /// [`TransportError::Bootstrap`]: retryable with backoff, since the
    /// network may simply be slow or degraded rather than broken.
    BootstrapTimeout,

    /// A `TransportAddr` string was malformed. Not retryable — the
    /// caller must supply a different address.
    InvalidAddress(String),

    /// A `TorTransportConfig` was rejected at construction (e.g. a
    /// zero `bootstrap_timeout`, or `state_dir`/`cache_dir` could not
    /// be created). Not retryable without changing the configuration.
    InvalidConfig(String),

    /// Dialing a peer failed (unreachable, circuit build failure).
    Connect(String),

    /// Launching an onion service failed (rejected configuration, key
    /// conflict, or hosting disabled in this client's configuration).
    HostingFailed(String),

    /// An I/O failure on an already-established stream.
    Io(std::io::Error),

    /// `TransportListener::accept` was called after the listener was
    /// shut down. Distinct from [`TransportError::Io`]: this means
    /// stop calling `accept`, not that one particular accepted stream
    /// failed.
    ListenerClosed,
}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        TransportError::Io(err)
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Bootstrap(msg) => write!(f, "Tor bootstrap failed: {msg}"),
            TransportError::BootstrapTimeout => {
                f.write_str("Tor bootstrap did not complete within the configured timeout")
            }
            TransportError::InvalidAddress(msg) => write!(f, "invalid transport address: {msg}"),
            TransportError::InvalidConfig(msg) => {
                write!(f, "invalid Tor transport configuration: {msg}")
            }
            TransportError::Connect(msg) => write!(f, "connect failed: {msg}"),
            TransportError::HostingFailed(msg) => {
                write!(f, "hosting an onion service failed: {msg}")
            }
            TransportError::Io(err) => write!(f, "transport I/O error: {err}"),
            TransportError::ListenerClosed => f.write_str("listener has been shut down"),
        }
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::{NetError, TransportError};

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

    #[test]
    fn transport_error_display_includes_the_inner_message() {
        let err = TransportError::Connect("peer unreachable".to_string());
        let rendered = err.to_string();
        assert!(rendered.contains("peer unreachable"), "{rendered}");
    }

    #[test]
    fn transport_error_implements_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&TransportError::ListenerClosed);
    }

    #[test]
    fn io_error_converts_to_transport_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broke");
        let transport_err: TransportError = io_err.into();
        assert!(matches!(transport_err, TransportError::Io(_)));
    }
}
