//! BLAKE3-based Short Authentication Strings. See AEGIS.Plan.V0.2.md
//! Section 2. The ratchet layer supplies the transcript (typically
//! both parties' identity public keys); this module only hashes and
//! formats it for out-of-band human comparison.

/// Hash a verification transcript (e.g. both parties' identity public
/// keys, concatenated in a fixed order) with BLAKE3.
pub fn sas_digest(transcript: &[u8]) -> [u8; 32] {
    *blake3::hash(transcript).as_bytes()
}

/// Format a digest as 5 space-separated 4-digit groups (20 chars) for
/// side-by-side human comparison, in the spirit of Signal's safety
/// numbers. Uses the first 8 bytes of the digest, each pair of bytes
/// reduced mod 10000.
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
