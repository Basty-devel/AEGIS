//! The `Transport` seam: [`TransportAddr`], the validated v3 onion
//! address type every implementation dials and is reached by. The
//! `Transport`/`TransportListener` traits themselves are added in the
//! next task.
//!
//! See `docs/superpowers/specs/2026-09-12-aegis-net-transport-phase1-design.md`
//! for the full design rationale (why v2 addresses are rejected, why
//! this is a validated newtype rather than a raw `String`).

use crate::error::TransportError;
use std::fmt;

/// A v3 onion address label is exactly this many base32 characters
/// (35 bytes of pubkey+checksum+version, base32-encoded).
const V3_LABEL_LEN: usize = 56;

/// A v2 onion address label is exactly this many base32 characters —
/// checked for explicitly so a v2 address gets a specific, actionable
/// error rather than a generic "wrong length" message.
const V2_LABEL_LEN: usize = 16;

/// A validated Tor v3 onion service address and port, e.g.
/// `"<56-char-base32-label>.onion:9001"`. Rejects v2 addresses
/// (16-character label) outright — v2 is deprecated network-wide, so
/// this crate does not support dialing or presenting one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransportAddr {
    host: String,
    port: u16,
}

impl TransportAddr {
    /// Parses `"<label>.onion:<port>"`.
    pub fn parse(s: &str) -> Result<Self, TransportError> {
        let (host, port_str) = s.rsplit_once(':').ok_or_else(|| {
            TransportError::InvalidAddress(format!("`{s}` is missing a `:port` suffix"))
        })?;
        let port: u16 = port_str.parse().map_err(|_| {
            TransportError::InvalidAddress(format!("`{port_str}` in `{s}` is not a valid port"))
        })?;
        Self::validate_onion_host(host)?;
        Ok(TransportAddr {
            host: host.to_string(),
            port,
        })
    }

    fn validate_onion_host(host: &str) -> Result<(), TransportError> {
        let label = host.strip_suffix(".onion").ok_or_else(|| {
            TransportError::InvalidAddress(format!("`{host}` does not end in `.onion`"))
        })?;
        if label.len() == V2_LABEL_LEN {
            return Err(TransportError::InvalidAddress(format!(
                "`{host}` is a {V2_LABEL_LEN}-character v2 onion address; v2 is deprecated and not supported"
            )));
        }
        if label.len() != V3_LABEL_LEN {
            return Err(TransportError::InvalidAddress(format!(
                "`{host}` has a {}-character label; a v3 onion address label must be exactly {V3_LABEL_LEN} characters",
                label.len()
            )));
        }
        if !label.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
            return Err(TransportError::InvalidAddress(format!(
                "`{host}` contains a character outside the base32 alphabet (`a`-`z`, `2`-`7`)"
            )));
        }
        Ok(())
    }

    /// The `<label>.onion` host, without the port.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The `(host, port)` pair `arti_client::IntoTorAddr` accepts.
    pub fn as_host_port(&self) -> (&str, u16) {
        (&self.host, self.port)
    }
}

impl fmt::Display for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// A byte-stream transport: dial a peer's [`TransportAddr`], or host
/// one of your own and accept incoming connections. Implemented by
/// `crate::tor::TorTransport` (real, Tor-backed) and
/// `crate::fake::FakeTransport` (in-memory, test-only).
///
/// `Stream` is `Read + Write`, not async — this lets a `Self::Stream`
/// be handed directly to `aegis-ratchet`'s envelope serialization or
/// `aegis-file`'s `encrypt_stream`/`decrypt_stream` without an adapter.
/// See the design doc's "Sync Facade" section.
pub trait Transport {
    /// The connected byte stream this transport produces.
    type Stream: std::io::Read + std::io::Write + Send;
    /// The listener this transport's [`Transport::host`] produces.
    type Listener: TransportListener<Stream = Self::Stream>;

    /// Dials `addr`, blocking until the connection is established or
    /// fails.
    fn connect(&self, addr: &TransportAddr) -> Result<Self::Stream, TransportError>;

    /// Hosts a listener reachable at some [`TransportAddr`] (see
    /// [`TransportListener::local_addr`]). `nickname` identifies this
    /// hosting session to the underlying implementation (e.g. maps to
    /// `arti`'s `HsNickname` for a real onion service). Blocks only
    /// long enough to start hosting — accepting connections happens via
    /// the returned listener's [`TransportListener::accept`].
    fn host(&self, nickname: &str) -> Result<Self::Listener, TransportError>;
}

/// A listening endpoint produced by [`Transport::host`].
pub trait TransportListener {
    /// The connected byte stream [`TransportListener::accept`]
    /// produces — always the same type as its owning
    /// [`Transport::Stream`].
    type Stream: std::io::Read + std::io::Write + Send;

    /// Blocks until a peer connects, or the listener errors.
    fn accept(&self) -> Result<Self::Stream, TransportError>;

    /// The address a peer would dial to reach this listener.
    fn local_addr(&self) -> TransportAddr;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_v3_label() -> String {
        "a".repeat(V3_LABEL_LEN)
    }

    #[test]
    fn valid_v3_address_parses() {
        let addr_str = format!("{}.onion:9001", valid_v3_label());
        let addr = TransportAddr::parse(&addr_str).expect("should parse");
        assert_eq!(addr.port(), 9001);
        assert_eq!(addr.host(), format!("{}.onion", valid_v3_label()));
    }

    #[test]
    fn missing_port_is_rejected() {
        let addr_str = format!("{}.onion", valid_v3_label());
        let err = TransportAddr::parse(&addr_str).unwrap_err();
        assert!(matches!(err, TransportError::InvalidAddress(_)));
    }

    #[test]
    fn non_numeric_port_is_rejected() {
        let addr_str = format!("{}.onion:notaport", valid_v3_label());
        let err = TransportAddr::parse(&addr_str).unwrap_err();
        assert!(matches!(err, TransportError::InvalidAddress(_)));
    }

    #[test]
    fn port_out_of_u16_range_is_rejected() {
        let addr_str = format!("{}.onion:70000", valid_v3_label());
        let err = TransportAddr::parse(&addr_str).unwrap_err();
        assert!(matches!(err, TransportError::InvalidAddress(_)));
    }

    #[test]
    fn missing_onion_suffix_is_rejected() {
        let addr_str = format!("{}.com:9001", valid_v3_label());
        let err = TransportAddr::parse(&addr_str).unwrap_err();
        assert!(matches!(err, TransportError::InvalidAddress(_)));
    }

    #[test]
    fn v2_address_length_is_rejected_with_specific_message() {
        let addr_str = format!("{}.onion:9001", "a".repeat(V2_LABEL_LEN));
        let err = TransportAddr::parse(&addr_str).unwrap_err();
        match err {
            TransportError::InvalidAddress(msg) => assert!(msg.contains("v2"), "{msg}"),
            other => panic!("expected InvalidAddress, got {other:?}"),
        }
    }

    #[test]
    fn label_wrong_length_other_than_v2_is_rejected() {
        let addr_str = format!("{}.onion:9001", "a".repeat(V3_LABEL_LEN - 1));
        let err = TransportAddr::parse(&addr_str).unwrap_err();
        assert!(matches!(err, TransportError::InvalidAddress(_)));
    }

    #[test]
    fn label_with_invalid_character_is_rejected() {
        let mut label = valid_v3_label();
        label.replace_range(0..1, "1"); // '1' is outside a-z,2-7
        let addr_str = format!("{label}.onion:9001");
        let err = TransportAddr::parse(&addr_str).unwrap_err();
        assert!(matches!(err, TransportError::InvalidAddress(_)));
    }

    #[test]
    fn label_with_uppercase_character_is_rejected() {
        let mut label = valid_v3_label();
        label.replace_range(0..1, "A");
        let addr_str = format!("{label}.onion:9001");
        let err = TransportAddr::parse(&addr_str).unwrap_err();
        assert!(matches!(err, TransportError::InvalidAddress(_)));
    }

    #[test]
    fn display_round_trips_host_and_port() {
        let addr_str = format!("{}.onion:9001", valid_v3_label());
        let addr = TransportAddr::parse(&addr_str).expect("should parse");
        assert_eq!(addr.to_string(), addr_str);
    }

    #[test]
    fn as_host_port_matches_accessors() {
        let addr_str = format!("{}.onion:9001", valid_v3_label());
        let addr = TransportAddr::parse(&addr_str).expect("should parse");
        assert_eq!(addr.as_host_port(), (addr.host(), addr.port()));
    }
}
