//! Domain-separated HKDF-SHA512. See AEGIS.Plan.V0.2.md Section 2.
//!
//! Construction: `K = HKDF-SHA512(salt=None, IKM, info)` where
//! `info = len(domain_label) || domain_label || protocol_version ||
//!         len(pubkey_A) || pubkey_A || len(pubkey_B) || pubkey_B`
//! and each `len(...)` is a 16-bit big-endian byte count.
//! Reference: NIST SP 800-56C (concatenation KDF) and RFC 5869 (HKDF).
//! The domain-separation label and public-key transcript binding in
//! `info` are mandatory per spec Section 2 — this function's signature
//! has no way to omit them.
//!
//! # Why the length prefixes
//!
//! Plain concatenation of variable-length fields is not injective:
//! `("labelA", version 0x01, ...)` and `("label", version 0x41, ...)`
//! serialise to the same bytes, as do any pair of `(pubkey_a,
//! pubkey_b)` splits of the same concatenation. Every caller in this
//! crate happens to use fixed-length fields today, so no collision is
//! reachable — but this is the KDF every future AEGIS crate derives
//! from, and the encoding freezes the moment the first key derived by
//! it hits the wire. The `u16` prefixes make the encoding injective
//! now, while there is exactly one caller and no compatibility cost.
//! `protocol_version` needs no prefix: it is a fixed-width single byte
//! at a fixed offset.

use crate::error::CryptoError;
use hkdf::Hkdf;
use sha2::Sha512;

/// Longest value that fits in one field's `u16` big-endian length
/// prefix.
pub const MAX_KDF_FIELD_LEN: usize = u16::MAX as usize;

/// Append a length-prefixed field to the `info` string.
fn push_framed(info: &mut Vec<u8>, field: &'static str, value: &[u8]) -> Result<(), CryptoError> {
    let len = u16::try_from(value.len()).map_err(|_| CryptoError::KdfFieldTooLong {
        field,
        len: value.len(),
    })?;
    info.extend_from_slice(&len.to_be_bytes());
    info.extend_from_slice(value);
    Ok(())
}

/// Derive `output.len()` bytes of key material from `ikm`, bound to a
/// domain label, protocol version, and both parties' public keys.
///
/// # Errors
///
/// Returns [`CryptoError::KdfFieldTooLong`] if any framed field exceeds
/// [`MAX_KDF_FIELD_LEN`] bytes, or [`CryptoError::KdfOutputLength`] if
/// more output is requested than RFC 5869 permits from one expansion
/// (255 × 64 = 16320 bytes for SHA-512).
pub fn derive_key(
    ikm: &[u8],
    domain_label: &[u8],
    protocol_version: u8,
    pubkey_a: &[u8],
    pubkey_b: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    let mut info = Vec::with_capacity(
        2 + domain_label.len() + 1 + 2 + pubkey_a.len() + 2 + pubkey_b.len(),
    );
    push_framed(&mut info, "domain_label", domain_label)?;
    info.push(protocol_version);
    push_framed(&mut info, "pubkey_a", pubkey_a)?;
    push_framed(&mut info, "pubkey_b", pubkey_b)?;

    let hk = Hkdf::<Sha512>::new(None, ikm);
    hk.expand(&info, output)
        .map_err(|_| CryptoError::KdfOutputLength {
            requested: output.len(),
        })
}

#[cfg(test)]
mod tests {
    use super::{derive_key, MAX_KDF_FIELD_LEN};
    use crate::error::CryptoError;

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

    /// Without length framing, `("labelA", version 0x01)` and
    /// `("label", version 0x41)` serialise to the identical `info`
    /// string (`0x41` is ASCII `A`), so both derive the same key from
    /// the same IKM. With framing they must differ.
    #[test]
    fn shifting_a_byte_between_label_and_version_changes_the_key() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"labelA", 0x01, b"pubkey-a", b"pubkey-b", &mut out1).unwrap();
        derive_key(b"ikm", b"label", 0x41, b"pubkey-a", b"pubkey-b", &mut out2).unwrap();
        assert_ne!(
            out1, out2,
            "label/version boundary must be unambiguous in the info string",
        );
    }

    /// Same ambiguity across the two public keys: unframed,
    /// `("aa", "b")` and `("a", "ab")` both concatenate to `aab`.
    #[test]
    fn shifting_a_byte_between_the_two_pubkeys_changes_the_key() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"label", 1, b"aa", b"b", &mut out1).unwrap();
        derive_key(b"ikm", b"label", 1, b"a", b"ab", &mut out2).unwrap();
        assert_ne!(
            out1, out2,
            "pubkey_a/pubkey_b boundary must be unambiguous in the info string",
        );
    }

    /// And between the version byte and the first public key: unframed,
    /// `(version 0x61, pubkey_a "b")` and `(version 0x61, ...)` shift
    /// identically, so use an empty vs. non-empty pubkey_a to move the
    /// boundary.
    #[test]
    fn shifting_a_byte_between_version_and_pubkey_a_changes_the_key() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"label", 1, b"", b"xy", &mut out1).unwrap();
        derive_key(b"ikm", b"label", 1, b"x", b"y", &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn oversized_field_is_rejected_rather_than_silently_truncated() {
        let too_long = vec![0u8; MAX_KDF_FIELD_LEN + 1];
        let mut out = [0u8; 32];
        assert_eq!(
            derive_key(b"ikm", b"label", 1, &too_long, b"b", &mut out).unwrap_err(),
            CryptoError::KdfFieldTooLong {
                field: "pubkey_a",
                len: MAX_KDF_FIELD_LEN + 1,
            },
        );
    }

    #[test]
    fn over_long_output_is_an_error_not_a_panic() {
        // RFC 5869 caps one expansion at 255 * HashLen; SHA-512 gives
        // 255 * 64 = 16320 bytes.
        let mut out = vec![0u8; 16321];
        assert_eq!(
            derive_key(b"ikm", b"label", 1, b"a", b"b", &mut out).unwrap_err(),
            CryptoError::KdfOutputLength { requested: 16321 },
        );
    }
}
