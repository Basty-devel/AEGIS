//! Protocol version and algorithm-suite negotiation table. See
//! AEGIS.Plan.V0.2.md Section 2 (crypto-agility requirement).

/// The AegisPQC wire protocol version, as bound into the hybrid KEM
/// KDF info by [`crate::hybrid::hybrid_kem_encapsulate`]/
/// [`crate::hybrid::hybrid_kem_decapsulate`].
///
/// Only constructible from a valid wire byte via
/// [`parse_protocol_version`] — there is no way to reach the KDF with
/// an unrecognised version, by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// Protocol version 1, the only version defined so far.
    V1 = 1,
}

/// Parse a raw wire version byte into a [`ProtocolVersion`], rejecting
/// anything not currently recognised.
pub fn parse_protocol_version(byte: u8) -> Option<ProtocolVersion> {
    match byte {
        1 => Some(ProtocolVersion::V1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_version_byte_parses() {
        assert_eq!(parse_protocol_version(1), Some(ProtocolVersion::V1));
    }

    #[test]
    fn unknown_version_byte_is_rejected() {
        assert_eq!(parse_protocol_version(99), None);
    }
}
