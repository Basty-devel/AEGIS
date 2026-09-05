//! Protocol version and algorithm-suite negotiation table. See
//! AEGIS.Plan.V0.2.md Section 2 (crypto-agility requirement).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1 = 1,
}

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
