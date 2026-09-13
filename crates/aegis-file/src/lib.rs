//! Chunked AEAD file streaming engine (up to 1 GiB), BLAKE3 Merkle tree
//! verification, and bounded 4 MiB transient memory buffering.
//!
//! See `AEGIS.Plan.V0.2.md` Section 5. Depends on `aegis-crypto` only —
//! no dependency on `aegis-ratchet` or `aegis-vault`, matching the
//! dependency order in Section 10.
//!
//! # What this crate is
//!
//! A pure, synchronous streaming engine — no networking, no storage,
//! no knowledge of `aegis-net`'s mailbox protocol or `aegis-vault`'s
//! database. You hand it a `Read`/`Write` pair, a key, and a length;
//! it hands back (on encrypt) or checks against (on decrypt) a
//! [`FileManifest`]. Callers own key lifecycle, transport, and where
//! the manifest's root hash actually travels (the authenticated
//! PQ-Double-Ratchet envelope, per spec Section 5 — this crate has no
//! ratchet dependency and therefore cannot enforce that itself; see
//! [`stream::decrypt_stream`]'s doc comment for exactly what it does
//! and does not verify).
//!
//! Two building blocks:
//!
//! 1. [`stream`] — [`stream::encrypt_stream`] / [`stream::decrypt_stream`],
//!    the chunked AEAD engine. Never buffers more than one
//!    [`stream::CHUNK_SIZE`]-sized (4 MiB) chunk of plaintext or
//!    ciphertext at a time, regardless of total file size, up to the
//!    [`stream::MAX_FILE_SIZE`] (1 GiB) cap.
//! 2. [`merkle`] — [`merkle::MerkleTree`], an RFC 6962-style Merkle tree
//!    over ciphertext-chunk hashes (BLAKE3 substituted for SHA-256).
//!    `stream` uses this internally to compute and verify whole-file
//!    root hashes; it is also exposed directly for a future
//!    partial/resumable-download path (`aegis-net`) that wants
//!    per-chunk inclusion proofs before the whole file has arrived.
//!
//! # Memory bounding
//!
//! The 4 MiB bound is on *chunk payload* buffers only. The Merkle leaf
//! list ([`merkle::leaf_hash`] outputs, 32 bytes each) is held in full
//! for the file's duration — at the 1 GiB / 4 MiB = 256-chunk cap, that
//! is 8 KiB, not a payload-scale allocation.
//!
//! # Panics
//!
//! Nothing in this crate panics on data an attacker controls — a
//! malformed wire header, a tampered or truncated ciphertext stream,
//! and a wrong key all return [`error::FileError`]. The only panic
//! this crate can reach is `aegis_crypto::aead::ChunkNonceSequence::random`'s
//! documented fail-closed reaction to OS RNG failure, which is not
//! attacker-controlled; see that type's own documentation.

#![warn(missing_docs)]

/// AegisPQC's file-streaming engine is NOT independently audited. Do
/// not rely on this code for life-critical communications until a
/// third-party cryptographic audit has been completed. See
/// `AEGIS.Plan.V0.2.md`, document header, and Section 9.1.
pub const SECURITY_DISCLAIMER: &str = aegis_crypto::SECURITY_DISCLAIMER;

pub mod error;
pub mod merkle;
pub mod stream;

pub use error::FileError;
pub use stream::{
    chunk_count_for, decrypt_stream, encrypt_stream, FileManifest, CHUNK_SIZE, MAX_CHUNKS,
    MAX_FILE_SIZE,
};

#[cfg(test)]
mod tests {
    use super::SECURITY_DISCLAIMER;

    #[test]
    fn disclaimer_states_not_audited() {
        assert!(SECURITY_DISCLAIMER.contains("NOT independently audited"));
    }
}
