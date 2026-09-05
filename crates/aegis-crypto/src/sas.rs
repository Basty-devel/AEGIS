//! BLAKE3-based Short Authentication Strings. See AEGIS.Plan.V0.2.md
//! Section 2. The ratchet layer supplies the transcript (typically
//! both parties' identity public keys); this module only hashes and
//! formats it for out-of-band human comparison.

/// BLAKE3 key-derivation context for AegisPQC short authentication
/// strings.
///
/// BLAKE3's `derive_key` context is required by its own documentation
/// to be hardcoded, globally unique, and application-specific — so it
/// is a `const` here rather than a parameter, and must never be
/// changed once shipped (changing it changes every SAS, which would
/// make previously-compared safety numbers stop matching).
pub const SAS_CONTEXT: &str = "AegisPQC v1 SAS";

/// Hash a verification transcript (e.g. both parties' identity public
/// keys, concatenated in a fixed order) with keyed BLAKE3.
///
/// Uses `blake3::derive_key` with [`SAS_CONTEXT`] rather than plain
/// `blake3::hash`. Spec Section 2 specifies SAS "generated via BLAKE3
/// key hashing," and this is also the only place in the crate that
/// would otherwise lack domain separation: an unkeyed hash of a
/// transcript is the same value everywhere it appears, so a SAS digest
/// could be confused with — or replayed from — any other unkeyed
/// BLAKE3 hash of the same bytes computed for a different purpose.
///
/// `derive_key` is preferred over `keyed_hash` because it takes a
/// human-readable context string directly, rather than requiring a
/// 32-byte key we would have to invent and then justify.
pub fn sas_digest(transcript: &[u8]) -> [u8; 32] {
    blake3::derive_key(SAS_CONTEXT, transcript)
}

/// Format a digest as 5 space-separated 4-digit groups (24 chars
/// including the 4 separating spaces) for side-by-side human
/// comparison, in the spirit of Signal's safety numbers. Uses the
/// first 10 bytes of the digest, each pair of bytes reduced mod 10000.
pub fn sas_display(digest: &[u8; 32]) -> String {
    let mut groups = Vec::with_capacity(5);
    for chunk in digest[..10].chunks(2) {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]) % 10000;
        groups.push(format!("{value:04}"));
    }
    groups.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_transcript_gives_same_digest() {
        assert_eq!(sas_digest(b"alice-pub||bob-pub"), sas_digest(b"alice-pub||bob-pub"));
    }

    /// The whole point of I4: a SAS digest must not be the same value
    /// as a plain unkeyed BLAKE3 hash of the same transcript. If this
    /// ever passes by equality, domain separation has been lost.
    #[test]
    fn digest_is_domain_separated_from_unkeyed_blake3() {
        let transcript = b"alice-pub||bob-pub";
        assert_ne!(
            sas_digest(transcript),
            *blake3::hash(transcript).as_bytes(),
            "SAS must use keyed BLAKE3, not blake3::hash",
        );
    }

    /// A different context string must produce a different digest —
    /// proves the context is actually mixed in rather than ignored.
    #[test]
    fn a_different_context_gives_a_different_digest() {
        let transcript = b"alice-pub||bob-pub";
        assert_ne!(
            sas_digest(transcript),
            blake3::derive_key("AegisPQC v1 SAS (not)", transcript),
        );
    }

    /// Pins the context string itself. Changing `SAS_CONTEXT` changes
    /// every safety number users have ever compared, so it should
    /// require deliberately editing this test.
    #[test]
    fn context_string_is_the_documented_one() {
        assert_eq!(SAS_CONTEXT, "AegisPQC v1 SAS");
    }

    #[test]
    fn different_transcript_gives_different_digest() {
        assert_ne!(sas_digest(b"alice-pub||bob-pub"), sas_digest(b"bob-pub||alice-pub"));
    }

    #[test]
    fn display_is_fixed_length_numeric() {
        let digest = sas_digest(b"some transcript");
        let display = sas_display(&digest);
        // 5 groups of 4 digits (20 chars) plus 4 separating spaces = 24.
        assert_eq!(display.len(), 24, "5 space-separated groups of 4 digits");
        assert!(display.chars().all(|c| c.is_ascii_digit() || c == ' '));
    }
}
