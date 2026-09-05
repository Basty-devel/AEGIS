//! Domain-separated HKDF-SHA512. See AEGIS.Plan.V0.2.md Section 2.
//!
//! Construction: `K = HKDF-SHA512(salt=None, IKM, info)` where
//! `info = domain_label || protocol_version || pubkey_A || pubkey_B`.
//! Reference: NIST SP 800-56C (concatenation KDF) and RFC 5869 (HKDF).
//! The domain-separation label and public-key transcript binding in
//! `info` are mandatory per spec Section 2 — this function's signature
//! has no way to omit them.

use hkdf::Hkdf;
use sha2::Sha512;

/// Derive `output.len()` bytes of key material from `ikm`, bound to a
/// domain label, protocol version, and both parties' public keys.
pub fn derive_key(
    ikm: &[u8],
    domain_label: &[u8],
    protocol_version: u8,
    pubkey_a: &[u8],
    pubkey_b: &[u8],
    output: &mut [u8],
) -> Result<(), hkdf::InvalidLength> {
    let mut info = Vec::with_capacity(domain_label.len() + 1 + pubkey_a.len() + pubkey_b.len());
    info.extend_from_slice(domain_label);
    info.push(protocol_version);
    info.extend_from_slice(pubkey_a);
    info.extend_from_slice(pubkey_b);

    let hk = Hkdf::<Sha512>::new(None, ikm);
    hk.expand(&info, output)
}

#[cfg(test)]
mod tests {
    use super::derive_key;

    #[test]
    fn same_inputs_are_deterministic() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"label", 1, b"pubkey-a", b"pubkey-b", &mut out1).unwrap();
        derive_key(b"ikm", b"label", 1, b"pubkey-a", b"pubkey-b", &mut out2).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn different_domain_labels_produce_different_output() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"label-a", 1, b"pubkey-a", b"pubkey-b", &mut out1).unwrap();
        derive_key(b"ikm", b"label-b", 1, b"pubkey-a", b"pubkey-b", &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn different_protocol_versions_produce_different_output() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"label", 1, b"pubkey-a", b"pubkey-b", &mut out1).unwrap();
        derive_key(b"ikm", b"label", 2, b"pubkey-a", b"pubkey-b", &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn different_pubkeys_produce_different_output() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"label", 1, b"pubkey-a", b"pubkey-b", &mut out1).unwrap();
        derive_key(b"ikm", b"label", 1, b"pubkey-x", b"pubkey-y", &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn fills_requested_output_length() {
        let mut out = [0u8; 64];
        derive_key(b"ikm", b"label", 1, b"a", b"b", &mut out).unwrap();
        assert!(out.iter().any(|&b| b != 0));
    }
}
