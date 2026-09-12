//! Chunked AEAD file streaming: bounded 4 MiB buffering, up to 1 GiB
//! per file. See `AEGIS.Plan.V0.2.md` Section 5. Defends primarily
//! against **A2** (a relay never sees plaintext or the full file at
//! once — it only ever holds one 4 MiB ciphertext chunk in flight) and
//! enforces bounded memory use against a hostile or merely oversized
//! input.
//!
//! # Wire container format
//!
//! ```text
//! offset  size  field
//! 0       4     magic: b"AGF1"
//! 4       1     algorithm: 0 = AES-256-GCM, 1 = ChaCha20-Poly1305
//! 5       4     nonce salt (see aegis_crypto::aead::ChunkNonceSequence)
//! 9       8     plaintext_len, u64 big-endian
//! 17      4     chunk_count, u32 big-endian
//! 21      ..    chunk_count ciphertext chunks, back to back
//! ```
//!
//! No length prefix precedes each chunk: `plaintext_len` and
//! `chunk_count` alone determine every chunk's exact plaintext size
//! (every chunk is [`CHUNK_SIZE`] bytes of plaintext except the last,
//! which is the remainder), so every ciphertext chunk's length —
//! plaintext size plus the fixed 16-byte AEAD tag — is likewise
//! implied, not transmitted. This is deliberate: it removes a field an
//! attacker could otherwise desynchronise from the true chunk boundary.
//!
//! The BLAKE3 Merkle root ([`crate::merkle`]) is **not** part of this
//! container. Per spec Section 5, it travels through the authenticated
//! PQ-Double-Ratchet envelope alongside the file key and is supplied to
//! [`decrypt_stream`] as part of the caller's trusted
//! [`FileManifest`] — embedding it in the same untrusted stream a
//! malicious relay (adversary A2) controls would defeat its purpose as
//! an independently-authenticated value.
//!
//! # AAD binding — why the header is authenticated even though it
//! isn't encrypted
//!
//! `algorithm`, `plaintext_len`, and `chunk_count` travel in the clear
//! in the header, but every chunk's AEAD authenticated-associated-data
//! includes all three (see [`chunk_aad`]), plus that chunk's own index.
//! Without this, a relay could shorten a file by truncating trailing
//! chunks *and* patching `chunk_count`/`plaintext_len` in the header to
//! match — every remaining chunk would still individually authenticate
//! (its ciphertext and nonce are untouched), so decryption would
//! "succeed" on a silently truncated file. Binding the header fields
//! into every chunk's AAD means the attacker cannot patch the header
//! without invalidating every already-encrypted chunk, since they lack
//! the key to re-encrypt under the new AAD — see
//! [`tests::truncating_chunks_and_patching_the_header_is_detected`].
//! The chunk index is additionally bound for defence in depth on top of
//! the nonce counter already being index-derived (see
//! [`tests::reordering_two_chunks_fails_to_decrypt`]).

use crate::error::FileError;
use crate::merkle::{leaf_hash, MerkleTree};
use aegis_crypto::aead::{self, AeadAlgorithm, ChunkNonceSequence};
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Plaintext bytes per chunk (4 MiB), per spec Section 5.
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Maximum plaintext file size (1 GiB), per spec Section 5.
pub const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// `MAX_FILE_SIZE` expressed in whole [`CHUNK_SIZE`] chunks (256 — 1
/// GiB divides [`CHUNK_SIZE`] exactly).
pub const MAX_CHUNKS: u32 = (MAX_FILE_SIZE / CHUNK_SIZE as u64) as u32;

/// AEAD authentication tag length (AES-256-GCM and ChaCha20-Poly1305
/// both produce a 16-byte tag).
const AEAD_TAG_LEN: usize = 16;

const MAGIC: [u8; 4] = *b"AGF1";
const HEADER_LEN: usize = 4 + 1 + 4 + 8 + 4;

/// Domain-separation label mixed into every chunk's AAD (see the module
/// doc comment). Distinct from any label used elsewhere in this
/// workspace's KDFs — this is authenticated-associated-data, not key
/// material, but the same "never let two different purposes share a
/// label" discipline applies.
const CHUNK_AAD_LABEL: &[u8] = b"AEGIS-FILE-v1-chunk";

fn algorithm_to_byte(alg: AeadAlgorithm) -> u8 {
    match alg {
        AeadAlgorithm::Aes256Gcm => 0,
        AeadAlgorithm::ChaCha20Poly1305 => 1,
    }
}

fn algorithm_from_byte(byte: u8) -> Result<AeadAlgorithm, FileError> {
    match byte {
        0 => Ok(AeadAlgorithm::Aes256Gcm),
        1 => Ok(AeadAlgorithm::ChaCha20Poly1305),
        other => Err(FileError::UnknownAlgorithm { byte: other }),
    }
}

/// The number of [`CHUNK_SIZE`] chunks a plaintext of `plaintext_len`
/// bytes splits into (the last one holds the remainder, and may be
/// shorter than [`CHUNK_SIZE`]). A zero-byte plaintext splits into zero
/// chunks.
pub fn chunk_count_for(plaintext_len: u64) -> u32 {
    if plaintext_len == 0 {
        0
    } else {
        // Ceiling division without overflowing on plaintext_len == u64::MAX:
        // (len - 1) / CHUNK_SIZE + 1. Safe here because callers already
        // reject plaintext_len > MAX_FILE_SIZE before this is used to
        // size anything, but the arithmetic itself holds for any u64.
        (((plaintext_len - 1) / CHUNK_SIZE as u64) + 1) as u32
    }
}

/// The plaintext length of chunk `index` (0-based) out of `chunk_count`
/// total chunks for a plaintext of `plaintext_len` bytes: [`CHUNK_SIZE`]
/// for every chunk except the last, which holds the remainder.
fn chunk_plaintext_len(index: u32, plaintext_len: u64, chunk_count: u32) -> usize {
    if index + 1 == chunk_count {
        let consumed = index as u64 * CHUNK_SIZE as u64;
        (plaintext_len - consumed) as usize
    } else {
        CHUNK_SIZE
    }
}

fn chunk_aad(
    algorithm: AeadAlgorithm,
    plaintext_len: u64,
    chunk_count: u32,
    index: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD_LABEL.len() + 1 + 8 + 4 + 4);
    aad.extend_from_slice(CHUNK_AAD_LABEL);
    aad.push(algorithm_to_byte(algorithm));
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.extend_from_slice(&chunk_count.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

/// Read exactly `buf.len()` bytes, mapping a short read/EOF to
/// [`FileError::UnexpectedEndOfInput`] rather than the generic
/// `std::io::Error` a bare `read_exact` would give, so callers can
/// match on "input ended early" as its own case.
fn read_chunk_exact<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    chunk_index: u32,
) -> Result<(), FileError> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(FileError::UnexpectedEndOfInput { chunk_index })
        }
        Err(err) => Err(FileError::Io(err)),
    }
}

/// After the declared final chunk, the stream must be exhausted.
/// Reading even one more byte successfully means the input was longer
/// than declared.
fn assert_no_trailing_data<R: Read>(reader: &mut R) -> Result<(), FileError> {
    let mut probe = [0u8; 1];
    match reader.read(&mut probe)? {
        0 => Ok(()),
        _ => Err(FileError::TrailingData),
    }
}

/// The out-of-band metadata a caller must both receive (on decrypt, as
/// the trusted expectation — see the module doc comment) and produce
/// (on encrypt, to embed in the ratchet envelope) alongside a file's
/// ciphertext stream.
///
/// Deliberately does not include `K_file` itself: spec Section 5 is
/// explicit that only `K_file`, this metadata, and the root hash travel
/// through the ratchet envelope, and the key's lifecycle (generation,
/// ratchet-envelope encryption, zeroization) belongs to the caller, not
/// to a struct this crate hands back by value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileManifest {
    /// Which AEAD cipher the chunks are encrypted with.
    pub algorithm: AeadAlgorithm,
    /// The nonce salt (see `aegis_crypto::aead::ChunkNonceSequence`).
    pub salt: [u8; 4],
    /// Total plaintext length in bytes.
    pub plaintext_len: u64,
    /// Number of chunks the plaintext was split into.
    pub chunk_count: u32,
    /// The BLAKE3 Merkle root over all chunk ciphertexts (see
    /// [`crate::merkle`]).
    pub root_hash: [u8; 32],
}

/// Encrypt `plaintext_len` bytes read from `reader` as a chunked AEAD
/// container written to `writer`, returning the [`FileManifest`] the
/// caller must carry to the recipient through the authenticated ratchet
/// envelope (spec Section 5).
///
/// `plaintext_len` must be supplied by the caller (typically from
/// filesystem metadata) rather than discovered by reading `reader` to
/// completion first: this is what lets the [`FileError::FileTooLarge`]
/// check reject an oversized input before any byte is read, and what
/// lets the header be written before the first chunk — this function
/// never buffers more than one [`CHUNK_SIZE`]-sized chunk at a time,
/// regardless of total file size.
///
/// # Errors
///
/// - [`FileError::FileTooLarge`] if `plaintext_len` exceeds
///   [`MAX_FILE_SIZE`] — checked before any I/O.
/// - [`FileError::UnexpectedEndOfInput`] if `reader` produces fewer
///   than `plaintext_len` bytes.
/// - [`FileError::TrailingData`] if `reader` produces more than
///   `plaintext_len` bytes.
/// - [`FileError::Io`] for any other I/O failure on `reader`/`writer`.
pub fn encrypt_stream<R: Read, W: Write>(
    algorithm: AeadAlgorithm,
    key: &[u8; 32],
    plaintext_len: u64,
    mut reader: R,
    mut writer: W,
) -> Result<FileManifest, FileError> {
    if plaintext_len > MAX_FILE_SIZE {
        return Err(FileError::FileTooLarge {
            limit: MAX_FILE_SIZE,
            declared: plaintext_len,
        });
    }

    let chunk_count = chunk_count_for(plaintext_len);
    let mut nonce_seq = ChunkNonceSequence::random();
    let salt = nonce_seq.salt();

    writer.write_all(&MAGIC)?;
    writer.write_all(&[algorithm_to_byte(algorithm)])?;
    writer.write_all(&salt)?;
    writer.write_all(&plaintext_len.to_be_bytes())?;
    writer.write_all(&chunk_count.to_be_bytes())?;

    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut leaves = Vec::with_capacity(chunk_count as usize);

    for index in 0..chunk_count {
        let this_len = chunk_plaintext_len(index, plaintext_len, chunk_count);
        let plaintext_slice = &mut buf[..this_len];
        read_chunk_exact(&mut reader, plaintext_slice, index)?;

        let nonce = nonce_seq.next_nonce();
        let aad = chunk_aad(algorithm, plaintext_len, chunk_count, index);
        let ciphertext = aead::encrypt(algorithm, key, &nonce, &aad, plaintext_slice)
            .map_err(|_| FileError::EncryptionFailed { chunk_index: index })?;
        writer.write_all(&ciphertext)?;
        leaves.push(leaf_hash(&ciphertext));
    }

    assert_no_trailing_data(&mut reader)?;

    let root_hash = MerkleTree::from_leaf_hashes(leaves).root();

    Ok(FileManifest {
        algorithm,
        salt,
        plaintext_len,
        chunk_count,
        root_hash,
    })
}

fn parse_header<R: Read>(reader: &mut R) -> Result<FileManifest, FileError> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            FileError::UnexpectedEndOfInput { chunk_index: 0 }
        } else {
            FileError::Io(err)
        }
    })?;

    if header[0..4] != MAGIC {
        return Err(FileError::BadMagic);
    }
    let algorithm = algorithm_from_byte(header[4])?;
    let salt: [u8; 4] = header[5..9].try_into().expect("slice is exactly 4 bytes");
    let plaintext_len =
        u64::from_be_bytes(header[9..17].try_into().expect("slice is exactly 8 bytes"));
    let header_chunk_count =
        u32::from_be_bytes(header[17..21].try_into().expect("slice is exactly 4 bytes"));

    if plaintext_len > MAX_FILE_SIZE {
        return Err(FileError::DeclaredLengthTooLarge {
            limit: MAX_FILE_SIZE,
            declared: plaintext_len,
        });
    }

    let expected_chunk_count = chunk_count_for(plaintext_len);
    if header_chunk_count != expected_chunk_count {
        return Err(FileError::InconsistentHeader {
            plaintext_len,
            header_chunk_count,
            expected_chunk_count,
        });
    }

    Ok(FileManifest {
        algorithm,
        salt,
        plaintext_len,
        chunk_count: header_chunk_count,
        // The wire header carries no root hash (see the module doc
        // comment); the caller compares against their own trusted
        // `expected` manifest's root, not this placeholder.
        root_hash: [0u8; 32],
    })
}

/// Decrypt a chunked AEAD container read from `reader`, writing the
/// recovered plaintext to `writer`.
///
/// `expected` is the [`FileManifest`] the caller received through the
/// authenticated ratchet envelope — **not** read from `reader` itself.
/// Every field of the wire header is checked against it (algorithm,
/// salt, `plaintext_len`, `chunk_count`), and the BLAKE3 Merkle root
/// computed over the actually-received chunks is checked against
/// `expected.root_hash`, after every individual chunk has already
/// passed AEAD authentication. Plaintext is written for a chunk only
/// after that chunk's AEAD tag has verified — a chunk that fails
/// authentication is never written to `writer`, matching spec Section
/// 5's "verify each chunk's hash incrementally during download, before
/// writing to disk."
///
/// # Errors
///
/// - [`FileError::BadMagic`] / [`FileError::UnknownAlgorithm`] /
///   [`FileError::InconsistentHeader`] / [`FileError::DeclaredLengthTooLarge`]
///   for a malformed wire header, checked before `expected` is even
///   consulted.
/// - [`FileError::ManifestMismatch`] if a well-formed header disagrees
///   with `expected`.
/// - [`FileError::ChunkAuthenticationFailed`] if any chunk's AEAD tag
///   fails to verify.
/// - [`FileError::UnexpectedEndOfInput`] / [`FileError::TrailingData`]
///   for a stream shorter or longer than the header declares.
/// - [`FileError::MerkleRootMismatch`] if every chunk authenticates
///   individually but the whole-file root does not match
///   `expected.root_hash`.
pub fn decrypt_stream<R: Read, W: Write>(
    key: &[u8; 32],
    expected: &FileManifest,
    mut reader: R,
    mut writer: W,
) -> Result<(), FileError> {
    let header = parse_header(&mut reader)?;

    if header.algorithm != expected.algorithm
        || header.salt != expected.salt
        || header.plaintext_len != expected.plaintext_len
        || header.chunk_count != expected.chunk_count
    {
        return Err(FileError::ManifestMismatch);
    }

    let FileManifest {
        algorithm,
        salt,
        plaintext_len,
        chunk_count,
        ..
    } = *expected;

    let mut nonce_seq = ChunkNonceSequence::new(salt);
    let mut ciphertext_buf = Zeroizing::new(vec![0u8; CHUNK_SIZE + AEAD_TAG_LEN]);
    let mut leaves = Vec::with_capacity(chunk_count as usize);

    for index in 0..chunk_count {
        let this_plaintext_len = chunk_plaintext_len(index, plaintext_len, chunk_count);
        let this_ciphertext_len = this_plaintext_len + AEAD_TAG_LEN;
        let ciphertext_slice = &mut ciphertext_buf[..this_ciphertext_len];
        read_chunk_exact(&mut reader, ciphertext_slice, index)?;

        leaves.push(leaf_hash(ciphertext_slice));

        let nonce = nonce_seq.next_nonce();
        let aad = chunk_aad(algorithm, plaintext_len, chunk_count, index);
        let plaintext = aead::decrypt(algorithm, key, &nonce, &aad, ciphertext_slice)
            .map_err(|_| FileError::ChunkAuthenticationFailed { chunk_index: index })?;
        writer.write_all(&plaintext)?;
    }

    assert_no_trailing_data(&mut reader)?;

    let root_hash = MerkleTree::from_leaf_hashes(leaves).root();
    if root_hash != expected.root_hash {
        return Err(FileError::MerkleRootMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn round_trip(algorithm: AeadAlgorithm, plaintext: &[u8]) -> (FileManifest, Vec<u8>) {
        let key = [0x77u8; 32];
        let mut ciphertext = Vec::new();
        let manifest = encrypt_stream(
            algorithm,
            &key,
            plaintext.len() as u64,
            Cursor::new(plaintext),
            &mut ciphertext,
        )
        .unwrap();

        let mut recovered = Vec::new();
        decrypt_stream(&key, &manifest, Cursor::new(&ciphertext), &mut recovered).unwrap();
        (manifest, recovered)
    }

    #[test]
    fn chunk_count_for_zero_bytes_is_zero() {
        assert_eq!(chunk_count_for(0), 0);
    }

    #[test]
    fn chunk_count_for_exactly_one_chunk_is_one() {
        assert_eq!(chunk_count_for(CHUNK_SIZE as u64), 1);
    }

    #[test]
    fn chunk_count_for_one_byte_over_a_chunk_is_two() {
        assert_eq!(chunk_count_for(CHUNK_SIZE as u64 + 1), 2);
    }

    #[test]
    fn chunk_count_for_one_byte_under_a_chunk_is_one() {
        assert_eq!(chunk_count_for(CHUNK_SIZE as u64 - 1), 1);
    }

    #[test]
    fn max_file_size_is_exactly_max_chunks_full_chunks() {
        assert_eq!(chunk_count_for(MAX_FILE_SIZE), MAX_CHUNKS);
        assert_eq!(MAX_CHUNKS, 256);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let (manifest, recovered) = round_trip(AeadAlgorithm::Aes256Gcm, b"");
        assert_eq!(recovered, b"");
        assert_eq!(manifest.chunk_count, 0);
        assert_eq!(manifest.root_hash, *blake3::hash(&[]).as_bytes());
    }

    #[test]
    fn small_single_chunk_plaintext_round_trips_both_algorithms() {
        for algorithm in [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::ChaCha20Poly1305] {
            let (manifest, recovered) = round_trip(algorithm, b"hello aegis file streaming");
            assert_eq!(recovered, b"hello aegis file streaming");
            assert_eq!(manifest.chunk_count, 1);
        }
    }

    #[test]
    fn exactly_one_chunk_boundary_round_trips() {
        let plaintext = vec![0xAB; CHUNK_SIZE];
        let (manifest, recovered) = round_trip(AeadAlgorithm::Aes256Gcm, &plaintext);
        assert_eq!(recovered, plaintext);
        assert_eq!(manifest.chunk_count, 1);
    }

    #[test]
    fn one_byte_past_a_chunk_boundary_round_trips_as_two_chunks() {
        let mut plaintext = vec![0xCD; CHUNK_SIZE];
        plaintext.push(0xEF);
        let (manifest, recovered) = round_trip(AeadAlgorithm::ChaCha20Poly1305, &plaintext);
        assert_eq!(recovered, plaintext);
        assert_eq!(manifest.chunk_count, 2);
    }

    #[test]
    fn multi_chunk_plaintext_with_a_short_final_chunk_round_trips() {
        // 2 full chunks plus a short remainder chunk.
        let mut plaintext = vec![0u8; CHUNK_SIZE * 2 + 12_345];
        for (i, b) in plaintext.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let (manifest, recovered) = round_trip(AeadAlgorithm::Aes256Gcm, &plaintext);
        assert_eq!(recovered, plaintext);
        assert_eq!(manifest.chunk_count, 3);
    }

    #[test]
    fn declared_length_over_the_cap_is_rejected_without_touching_the_reader() {
        struct PanicsOnRead;
        impl Read for PanicsOnRead {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                panic!("encrypt_stream must reject an oversized declared length before reading");
            }
        }

        let key = [0u8; 32];
        let mut out = Vec::new();
        let err = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            MAX_FILE_SIZE + 1,
            PanicsOnRead,
            &mut out,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            FileError::FileTooLarge {
                limit: MAX_FILE_SIZE,
                declared,
            } if declared == MAX_FILE_SIZE + 1
        ));
        assert!(out.is_empty(), "no header should be written on rejection");
    }

    #[test]
    fn reader_shorter_than_declared_length_is_an_error() {
        let key = [0u8; 32];
        let mut out = Vec::new();
        // Declare 10 bytes but only supply 3.
        let err = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            10,
            Cursor::new(b"abc"),
            &mut out,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            FileError::UnexpectedEndOfInput { chunk_index: 0 }
        ));
    }

    #[test]
    fn reader_longer_than_declared_length_is_an_error() {
        let key = [0u8; 32];
        let mut out = Vec::new();
        // Declare 3 bytes but supply 5.
        let err = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            3,
            Cursor::new(b"abcde"),
            &mut out,
        )
        .unwrap_err();
        assert!(matches!(err, FileError::TrailingData));
    }

    #[test]
    fn tampered_ciphertext_byte_fails_chunk_authentication() {
        let key = [0x11u8; 32];
        let plaintext = b"a moderately sized message to encrypt for tampering";
        let mut ciphertext = Vec::new();
        let manifest = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            plaintext.len() as u64,
            Cursor::new(plaintext),
            &mut ciphertext,
        )
        .unwrap();

        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        let mut recovered = Vec::new();
        let err =
            decrypt_stream(&key, &manifest, Cursor::new(&ciphertext), &mut recovered).unwrap_err();
        assert!(matches!(
            err,
            FileError::ChunkAuthenticationFailed { chunk_index: 0 }
        ));
    }

    #[test]
    fn wrong_key_fails_chunk_authentication() {
        let key = [0x22u8; 32];
        let wrong_key = [0x33u8; 32];
        let plaintext = b"secret payload";
        let mut ciphertext = Vec::new();
        let manifest = encrypt_stream(
            AeadAlgorithm::ChaCha20Poly1305,
            &key,
            plaintext.len() as u64,
            Cursor::new(plaintext),
            &mut ciphertext,
        )
        .unwrap();

        let mut recovered = Vec::new();
        let err = decrypt_stream(
            &wrong_key,
            &manifest,
            Cursor::new(&ciphertext),
            &mut recovered,
        )
        .unwrap_err();
        assert!(matches!(err, FileError::ChunkAuthenticationFailed { .. }));
    }

    /// Two full-size chunks encrypted normally, then swapped in the
    /// ciphertext stream. Each chunk's nonce is derived from its
    /// original index (`ChunkNonceSequence`), so the chunk now at
    /// position 0 was actually encrypted with the nonce for index 1
    /// (and vice versa) — authentication must fail rather than silently
    /// decrypting the file out of order.
    #[test]
    fn reordering_two_chunks_fails_to_decrypt() {
        let key = [0x44u8; 32];
        let plaintext = vec![0u8; CHUNK_SIZE * 2];
        let mut ciphertext = Vec::new();
        let manifest = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            plaintext.len() as u64,
            Cursor::new(&plaintext),
            &mut ciphertext,
        )
        .unwrap();

        let header_len = HEADER_LEN;
        let chunk_ct_len = CHUNK_SIZE + AEAD_TAG_LEN;
        let (chunk0, chunk1) = {
            let body = &ciphertext[header_len..];
            (
                body[..chunk_ct_len].to_vec(),
                body[chunk_ct_len..chunk_ct_len * 2].to_vec(),
            )
        };
        let mut swapped = ciphertext[..header_len].to_vec();
        swapped.extend_from_slice(&chunk1);
        swapped.extend_from_slice(&chunk0);

        let mut recovered = Vec::new();
        let err =
            decrypt_stream(&key, &manifest, Cursor::new(&swapped), &mut recovered).unwrap_err();
        assert!(matches!(
            err,
            FileError::ChunkAuthenticationFailed { chunk_index: 0 }
        ));
    }

    /// Drop the trailing chunk and patch the header's `chunk_count`
    /// (and `plaintext_len`) to match, simulating a relay that
    /// truncates a file and tries to keep the container
    /// self-consistent. The AAD binding described in the module doc
    /// comment must catch this even though the remaining chunk's own
    /// ciphertext bytes are completely untouched.
    #[test]
    fn truncating_chunks_and_patching_the_header_is_detected() {
        let key = [0x55u8; 32];
        let plaintext = vec![0u8; CHUNK_SIZE + 100];
        let mut ciphertext = Vec::new();
        let manifest = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            plaintext.len() as u64,
            Cursor::new(&plaintext),
            &mut ciphertext,
        )
        .unwrap();
        assert_eq!(manifest.chunk_count, 2);

        // Keep only the first chunk's ciphertext bytes.
        let header_len = HEADER_LEN;
        let first_chunk_ct_len = CHUNK_SIZE + AEAD_TAG_LEN;
        let first_chunk = ciphertext[header_len..header_len + first_chunk_ct_len].to_vec();

        // Patch a fresh header claiming a single, full-length chunk.
        let patched_plaintext_len: u64 = CHUNK_SIZE as u64;
        let mut patched = Vec::new();
        patched.extend_from_slice(&MAGIC);
        patched.push(algorithm_to_byte(manifest.algorithm));
        patched.extend_from_slice(&manifest.salt);
        patched.extend_from_slice(&patched_plaintext_len.to_be_bytes());
        patched.extend_from_slice(&1u32.to_be_bytes());
        patched.extend_from_slice(&first_chunk);

        // An attacker without the ratchet-authenticated original
        // manifest might try to present a manifest consistent with
        // *this* patched header instead. But the caller here still
        // supplies the true `expected` manifest (that's the whole
        // point: the app layer never uses anything else), so the
        // header/`expected` comparison in `decrypt_stream` catches the
        // mismatch immediately.
        let mut recovered = Vec::new();
        let err =
            decrypt_stream(&key, &manifest, Cursor::new(&patched), &mut recovered).unwrap_err();
        assert!(matches!(err, FileError::ManifestMismatch));
    }

    /// Even if an attacker's patched header happened to match a
    /// (hypothetically compromised) `expected` manifest's
    /// `plaintext_len`/`chunk_count`/`algorithm`/`salt` fields exactly,
    /// the chunk AAD — computed from those same fields at encryption
    /// time — would not match what a *real* single-chunk file's chunk 0
    /// AAD looked like, so the surviving chunk still fails
    /// authentication. This directly tests the AAD-binding claim in the
    /// module doc comment, independent of the manifest-comparison guard
    /// tested above.
    #[test]
    fn aad_binding_alone_rejects_a_header_edited_to_match_a_truncated_chunk_set() {
        let key = [0x66u8; 32];
        let plaintext = vec![0u8; CHUNK_SIZE + 100];
        let mut ciphertext = Vec::new();
        let manifest = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            plaintext.len() as u64,
            Cursor::new(&plaintext),
            &mut ciphertext,
        )
        .unwrap();

        let header_len = HEADER_LEN;
        let first_chunk_ct_len = CHUNK_SIZE + AEAD_TAG_LEN;
        let first_chunk_ciphertext =
            ciphertext[header_len..header_len + first_chunk_ct_len].to_vec();

        // Directly attempt to decrypt just this chunk under the AAD a
        // genuine single-chunk, CHUNK_SIZE-byte file would have used —
        // simulating an attacker who also controls `expected` and sets
        // it to describe a single-chunk file.
        let forged_expected = FileManifest {
            algorithm: manifest.algorithm,
            salt: manifest.salt,
            plaintext_len: CHUNK_SIZE as u64,
            chunk_count: 1,
            root_hash: [0u8; 32], // irrelevant: chunk auth fails first
        };
        let mut forged_stream = Vec::new();
        forged_stream.extend_from_slice(&MAGIC);
        forged_stream.push(algorithm_to_byte(forged_expected.algorithm));
        forged_stream.extend_from_slice(&forged_expected.salt);
        forged_stream.extend_from_slice(&(CHUNK_SIZE as u64).to_be_bytes());
        forged_stream.extend_from_slice(&1u32.to_be_bytes());
        forged_stream.extend_from_slice(&first_chunk_ciphertext);

        let mut recovered = Vec::new();
        let err = decrypt_stream(
            &key,
            &forged_expected,
            Cursor::new(&forged_stream),
            &mut recovered,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            FileError::ChunkAuthenticationFailed { chunk_index: 0 }
        ));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let key = [0u8; 32];
        let mut bogus = vec![0u8; HEADER_LEN];
        bogus[0..4].copy_from_slice(b"NOPE");
        let expected = FileManifest {
            algorithm: AeadAlgorithm::Aes256Gcm,
            salt: [0; 4],
            plaintext_len: 0,
            chunk_count: 0,
            root_hash: [0; 32],
        };
        let mut recovered = Vec::new();
        let err = decrypt_stream(&key, &expected, Cursor::new(&bogus), &mut recovered).unwrap_err();
        assert!(matches!(err, FileError::BadMagic));
    }

    #[test]
    fn unknown_algorithm_byte_is_rejected() {
        let mut bogus = Vec::new();
        bogus.extend_from_slice(&MAGIC);
        bogus.push(99);
        bogus.extend_from_slice(&[0u8; 4]);
        bogus.extend_from_slice(&0u64.to_be_bytes());
        bogus.extend_from_slice(&0u32.to_be_bytes());

        let key = [0u8; 32];
        let expected = FileManifest {
            algorithm: AeadAlgorithm::Aes256Gcm,
            salt: [0; 4],
            plaintext_len: 0,
            chunk_count: 0,
            root_hash: [0; 32],
        };
        let mut recovered = Vec::new();
        let err = decrypt_stream(&key, &expected, Cursor::new(&bogus), &mut recovered).unwrap_err();
        assert!(matches!(err, FileError::UnknownAlgorithm { byte: 99 }));
    }

    #[test]
    fn inconsistent_header_chunk_count_is_rejected() {
        let mut bogus = Vec::new();
        bogus.extend_from_slice(&MAGIC);
        bogus.push(0);
        bogus.extend_from_slice(&[0u8; 4]);
        bogus.extend_from_slice(&(CHUNK_SIZE as u64 + 1).to_be_bytes()); // implies 2 chunks
        bogus.extend_from_slice(&1u32.to_be_bytes()); // header claims 1

        let key = [0u8; 32];
        let expected = FileManifest {
            algorithm: AeadAlgorithm::Aes256Gcm,
            salt: [0; 4],
            plaintext_len: CHUNK_SIZE as u64 + 1,
            chunk_count: 2,
            root_hash: [0; 32],
        };
        let mut recovered = Vec::new();
        let err = decrypt_stream(&key, &expected, Cursor::new(&bogus), &mut recovered).unwrap_err();
        assert!(matches!(
            err,
            FileError::InconsistentHeader {
                header_chunk_count: 1,
                expected_chunk_count: 2,
                ..
            }
        ));
    }

    #[test]
    fn declared_length_over_the_cap_in_the_wire_header_is_rejected() {
        let mut bogus = Vec::new();
        bogus.extend_from_slice(&MAGIC);
        bogus.push(0);
        bogus.extend_from_slice(&[0u8; 4]);
        bogus.extend_from_slice(&(MAX_FILE_SIZE + 1).to_be_bytes());
        bogus.extend_from_slice(&(MAX_CHUNKS + 1).to_be_bytes());

        let key = [0u8; 32];
        let expected = FileManifest {
            algorithm: AeadAlgorithm::Aes256Gcm,
            salt: [0; 4],
            plaintext_len: MAX_FILE_SIZE + 1,
            chunk_count: MAX_CHUNKS + 1,
            root_hash: [0; 32],
        };
        let mut recovered = Vec::new();
        let err = decrypt_stream(&key, &expected, Cursor::new(&bogus), &mut recovered).unwrap_err();
        assert!(matches!(
            err,
            FileError::DeclaredLengthTooLarge {
                limit: MAX_FILE_SIZE,
                ..
            }
        ));
    }

    #[test]
    fn merkle_root_mismatch_is_detected_even_when_every_chunk_authenticates() {
        let key = [0x88u8; 32];
        let plaintext = b"content whose chunks will all authenticate correctly";
        let mut ciphertext = Vec::new();
        let mut manifest = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            plaintext.len() as u64,
            Cursor::new(plaintext),
            &mut ciphertext,
        )
        .unwrap();

        // Corrupt only the expected root, leaving every chunk (and the
        // header) exactly as genuinely encrypted — proves the Merkle
        // check is independent of, and runs in addition to, per-chunk
        // AEAD authentication.
        manifest.root_hash[0] ^= 0xFF;

        let mut recovered = Vec::new();
        let err =
            decrypt_stream(&key, &manifest, Cursor::new(&ciphertext), &mut recovered).unwrap_err();
        assert!(matches!(err, FileError::MerkleRootMismatch));
    }

    #[test]
    fn trailing_garbage_after_the_final_chunk_is_rejected() {
        let key = [0x99u8; 32];
        let plaintext = b"short message";
        let mut ciphertext = Vec::new();
        let manifest = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            plaintext.len() as u64,
            Cursor::new(plaintext),
            &mut ciphertext,
        )
        .unwrap();
        ciphertext.push(0xFF);

        let mut recovered = Vec::new();
        let err =
            decrypt_stream(&key, &manifest, Cursor::new(&ciphertext), &mut recovered).unwrap_err();
        assert!(matches!(err, FileError::TrailingData));
    }

    #[test]
    fn truncated_stream_missing_the_final_chunk_is_rejected() {
        let key = [0xAAu8; 32];
        let plaintext = vec![0u8; CHUNK_SIZE + 500];
        let mut ciphertext = Vec::new();
        let manifest = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            plaintext.len() as u64,
            Cursor::new(&plaintext),
            &mut ciphertext,
        )
        .unwrap();

        let truncated = &ciphertext[..ciphertext.len() - 10];
        let mut recovered = Vec::new();
        let err =
            decrypt_stream(&key, &manifest, Cursor::new(truncated), &mut recovered).unwrap_err();
        assert!(matches!(
            err,
            FileError::UnexpectedEndOfInput { chunk_index: 1 }
        ));
    }

    #[test]
    fn manifests_produced_by_encryption_are_self_consistent() {
        let key = [0xBBu8; 32];
        let plaintext = vec![0u8; CHUNK_SIZE * 3 + 7];
        let mut ciphertext = Vec::new();
        let manifest = encrypt_stream(
            AeadAlgorithm::ChaCha20Poly1305,
            &key,
            plaintext.len() as u64,
            Cursor::new(&plaintext),
            &mut ciphertext,
        )
        .unwrap();
        assert_eq!(
            manifest.chunk_count,
            chunk_count_for(manifest.plaintext_len)
        );
        assert_eq!(manifest.plaintext_len, plaintext.len() as u64);
    }

    /// Two independent encryptions of the same plaintext must not
    /// produce the same salt (and therefore not the same ciphertext) —
    /// `ChunkNonceSequence::random` must actually be exercised, not a
    /// fixed value.
    #[test]
    fn repeated_encryption_of_the_same_plaintext_uses_fresh_salts() {
        let key = [0xCCu8; 32];
        let plaintext = b"same plaintext both times";
        let mut ct1 = Vec::new();
        let mut ct2 = Vec::new();
        let m1 = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            plaintext.len() as u64,
            Cursor::new(plaintext),
            &mut ct1,
        )
        .unwrap();
        let m2 = encrypt_stream(
            AeadAlgorithm::Aes256Gcm,
            &key,
            plaintext.len() as u64,
            Cursor::new(plaintext),
            &mut ct2,
        )
        .unwrap();
        assert_ne!(m1.salt, m2.salt);
        assert_ne!(ct1, ct2);
    }
}
