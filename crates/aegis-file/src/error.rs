//! Crate-wide error type for `aegis-file`.
//!
//! Every fallible operation that can be driven by attacker-controlled
//! bytes — a wire header, a ciphertext chunk, a declared plaintext
//! length — returns [`FileError`] rather than panicking. A relay-fed
//! stream (adversary A2, `AEGIS.Plan.V0.2.md` Section 1) is exactly the
//! input this crate must never trust enough to `unwrap()` against.
//!
//! The one deliberate exception is OS-RNG failure inside
//! `aegis_crypto::aead::ChunkNonceSequence::random`, which stays a
//! fail-closed panic there (see that crate's `error` module) rather
//! than surfacing here as a `FileError` variant: it is not
//! attacker-controlled, and this crate has no meaningful recovery from
//! "cannot obtain a nonce salt" beyond what that panic already does.

use core::fmt;

/// Errors returned by `aegis-file`'s streaming encrypt/decrypt engine.
///
/// Non-exhaustive: new failure modes may be added without a semver
/// break. Variants carry only length/index/shape information a peer
/// already controls or could derive from the ciphertext it sent — never
/// secret-dependent detail, so rendering or logging an error cannot
/// leak key material or plaintext.
#[derive(Debug)]
#[non_exhaustive]
pub enum FileError {
    /// Underlying reader/writer I/O failure not otherwise classified
    /// below (permission denied, disk full, broken pipe, and so on).
    Io(std::io::Error),

    /// A primitive-level cryptographic failure from `aegis-crypto`
    /// (used by the KDF/AEAD plumbing this crate calls into; AEAD
    /// authentication failure itself is reported as
    /// [`FileError::ChunkAuthenticationFailed`], not through this
    /// variant, so callers can match on the two independently).
    Crypto(aegis_crypto::CryptoError),

    /// The caller-declared plaintext length exceeds the spec Section 5
    /// cap (1 GiB). Returned by [`crate::stream::encrypt_stream`]
    /// before any byte is read from the caller's reader — the cap is
    /// enforced against the declared length up front, precisely so an
    /// oversized input cannot first be streamed through 4 MiB at a time
    /// only to be rejected at the end.
    FileTooLarge {
        /// The spec Section 5 cap in bytes (1 GiB).
        limit: u64,
        /// The declared plaintext length that exceeded it.
        declared: u64,
    },

    /// The wire header's fixed 4-byte magic did not match `b"AGF1"` —
    /// not an AegisPQC file container at all, or a different protocol
    /// version's container.
    BadMagic,

    /// The wire header's algorithm byte was not one of the two defined
    /// values (`0` = AES-256-GCM, `1` = ChaCha20-Poly1305).
    UnknownAlgorithm {
        /// The unrecognised byte.
        byte: u8,
    },

    /// The wire header's `chunk_count` field is not what
    /// [`crate::stream::chunk_count_for`] deterministically computes
    /// from the header's own `plaintext_len` field. A well-formed
    /// header can never disagree with itself this way; this only fires
    /// on a corrupted or adversarially crafted header, and is checked
    /// before any chunk is read so the failure is immediate rather than
    /// surfacing as a confusing later truncation error.
    InconsistentHeader {
        /// `plaintext_len` as read from the header.
        plaintext_len: u64,
        /// `chunk_count` as read from the header.
        header_chunk_count: u32,
        /// The value [`crate::stream::chunk_count_for`] computes from
        /// `plaintext_len`, which `header_chunk_count` should have
        /// equalled.
        expected_chunk_count: u32,
    },

    /// The wire header's own declared `plaintext_len` exceeds the spec
    /// Section 5 cap. Distinct from [`FileError::FileTooLarge`], which
    /// is the encrypt-side, caller-declared-length check: this is the
    /// decrypt-side check against a value read from an untrusted
    /// stream.
    DeclaredLengthTooLarge {
        /// The spec Section 5 cap in bytes (1 GiB).
        limit: u64,
        /// The declared plaintext length read from the wire header.
        declared: u64,
    },

    /// The wire header parsed successfully and is internally
    /// consistent, but its algorithm, salt, `plaintext_len`, or
    /// `chunk_count` field does not match the corresponding field of
    /// the [`crate::stream::FileManifest`] the caller supplied as the
    /// trusted, out-of-band expectation (in AegisPQC, the manifest
    /// travels through the authenticated PQ-Double-Ratchet envelope;
    /// the ciphertext stream itself does not, per spec Section 5 —
    /// adversary A2 controls the relay carrying it). This is the check
    /// that catches a relay serving a header-and-chunks pair that is
    /// internally self-consistent but does not match what the sender
    /// actually authenticated.
    ManifestMismatch,

    /// The stream ended (a `read` returned zero bytes, or `read_exact`
    /// hit EOF) before the declared `chunk_count` chunks — or, on the
    /// encrypt side, before the caller-declared `plaintext_len` bytes —
    /// had been fully read.
    UnexpectedEndOfInput {
        /// Index of the chunk that was being read when input ended.
        chunk_index: u32,
    },

    /// Extra bytes remained in the reader after the declared final
    /// chunk was fully consumed. On the encrypt side this means the
    /// reader produced more than the caller-declared `plaintext_len`
    /// bytes; on the decrypt side it means the ciphertext stream is
    /// longer than its own header declares.
    TrailingData,

    /// The underlying AEAD cipher rejected a chunk at encryption time.
    /// Unreachable in practice for this crate's own callers: both
    /// AES-256-GCM and ChaCha20-Poly1305 accept messages far larger
    /// than [`crate::stream::CHUNK_SIZE`] (RFC 8439's ~256 GiB bound is
    /// the smaller of the two limits), so no chunk this crate ever
    /// constructs can exceed either cipher's maximum message length.
    /// Kept as an explicit, non-panicking variant rather than an
    /// `unwrap()` so a future change that violates that invariant fails
    /// closed with a typed error instead of aborting the process.
    EncryptionFailed {
        /// Index of the chunk the underlying cipher rejected.
        chunk_index: u32,
    },

    /// AEAD authentication failed for one ciphertext chunk — tampered
    /// ciphertext, a chunk from a different position (the per-chunk
    /// nonce is derived from its index, so a relay-reordered or
    /// relay-substituted chunk fails this the same way corrupted bytes
    /// do), or the wrong key.
    ChunkAuthenticationFailed {
        /// Index of the chunk that failed to authenticate.
        chunk_index: u32,
    },

    /// Every individual chunk authenticated under its own AEAD tag, but
    /// the BLAKE3 Merkle root computed over all ciphertext-chunk leaves
    /// did not match the root the caller expected (normally the value
    /// carried in the authenticated ratchet envelope alongside the
    /// file key — see [`crate::merkle`]). This is a second,
    /// independent integrity check: it does not add security against
    /// an adversary who already holds the file key (they could
    /// recompute a matching root too), but it detects a relay serving
    /// an internally-consistent-looking short or reordered *set* of
    /// otherwise-genuine chunks whose per-chunk authentication alone
    /// would not reveal was incomplete.
    MerkleRootMismatch,

    /// [`crate::merkle::MerkleTree::generate_proof`] was asked for a
    /// leaf index that does not exist in the tree.
    MerkleIndexOutOfRange {
        /// The requested index.
        index: u32,
        /// The tree's actual leaf count.
        leaf_count: u32,
    },
}

impl From<std::io::Error> for FileError {
    fn from(err: std::io::Error) -> Self {
        FileError::Io(err)
    }
}

impl From<aegis_crypto::CryptoError> for FileError {
    fn from(err: aegis_crypto::CryptoError) -> Self {
        FileError::Crypto(err)
    }
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileError::Io(err) => write!(f, "I/O error: {err}"),
            FileError::Crypto(err) => write!(f, "cryptographic error: {err}"),
            FileError::FileTooLarge { limit, declared } => write!(
                f,
                "declared plaintext length {declared} bytes exceeds the {limit}-byte cap"
            ),
            FileError::BadMagic => {
                f.write_str("input is not an AegisPQC file container (bad magic)")
            }
            FileError::UnknownAlgorithm { byte } => {
                write!(f, "unknown AEAD algorithm byte {byte:#04x} in file header")
            }
            FileError::InconsistentHeader {
                plaintext_len,
                header_chunk_count,
                expected_chunk_count,
            } => write!(
                f,
                "file header is internally inconsistent: plaintext_len {plaintext_len} implies \
                 {expected_chunk_count} chunks, but header declares {header_chunk_count}"
            ),
            FileError::DeclaredLengthTooLarge { limit, declared } => write!(
                f,
                "file header declares plaintext length {declared} bytes, exceeding the \
                 {limit}-byte cap"
            ),
            FileError::ManifestMismatch => {
                f.write_str("file header does not match the expected manifest received out of band")
            }
            FileError::UnexpectedEndOfInput { chunk_index } => write!(
                f,
                "input ended unexpectedly while reading chunk {chunk_index}"
            ),
            FileError::TrailingData => {
                f.write_str("extra bytes remained after the declared final chunk")
            }
            FileError::EncryptionFailed { chunk_index } => {
                write!(
                    f,
                    "chunk {chunk_index} was rejected by the underlying AEAD cipher"
                )
            }
            FileError::ChunkAuthenticationFailed { chunk_index } => {
                write!(f, "chunk {chunk_index} failed AEAD authentication")
            }
            FileError::MerkleRootMismatch => {
                f.write_str("BLAKE3 Merkle root does not match the expected value")
            }
            FileError::MerkleIndexOutOfRange { index, leaf_count } => write!(
                f,
                "Merkle proof index {index} is out of range for a tree with {leaf_count} leaves"
            ),
        }
    }
}

impl std::error::Error for FileError {}

#[cfg(test)]
mod tests {
    use super::FileError;

    #[test]
    fn display_names_the_offending_lengths() {
        let err = FileError::FileTooLarge {
            limit: 1_073_741_824,
            declared: 2_000_000_000,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("2000000000"), "{rendered}");
        assert!(rendered.contains("1073741824"), "{rendered}");
    }

    #[test]
    fn implements_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&FileError::TrailingData);
    }

    #[test]
    fn io_error_converts() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let file_err: FileError = io_err.into();
        assert!(matches!(file_err, FileError::Io(_)));
    }

    #[test]
    fn crypto_error_converts() {
        let crypto_err = aegis_crypto::CryptoError::InvalidPeerPublicKey;
        let file_err: FileError = crypto_err.into();
        assert!(matches!(file_err, FileError::Crypto(_)));
    }

    #[test]
    fn chunk_authentication_failure_names_the_chunk_index() {
        let err = FileError::ChunkAuthenticationFailed { chunk_index: 41 };
        assert!(err.to_string().contains("41"));
    }

    #[test]
    fn inconsistent_header_names_all_three_values() {
        let err = FileError::InconsistentHeader {
            plaintext_len: 5_000_000,
            header_chunk_count: 1,
            expected_chunk_count: 2,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("5000000"), "{rendered}");
        assert!(rendered.contains("implies 2 chunks"), "{rendered}");
        assert!(rendered.contains("declares 1"), "{rendered}");
    }
}
