//! AES-256-GCM / ChaCha20-Poly1305 wrapper with mandated nonce
//! construction. See AEGIS.Plan.V0.2.md Section 2.
//!
//! Nonce construction: 32-bit random salt (generated once per
//! session/file) concatenated with a 64-bit big-endian monotonic
//! counter. See [`ChunkNonceSequence`] for the exact uniqueness
//! guarantee this does and does not provide.

use aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;

/// Produces 96-bit nonces: a fixed 32-bit random salt followed by a
/// 64-bit big-endian counter.
///
/// # Uniqueness guarantee — read this before reusing a key
///
/// Nonces are unique **within one sequence instance**, by construction:
/// the counter is strictly monotonic and cannot wrap without panicking.
///
/// They are **not** unconditionally unique across instances. Two
/// sequences built with the same salt emit exactly the same nonces, and
/// two independently random salts collide with probability governed by
/// the birthday bound on 32 bits — about 50% after roughly 77,000
/// sequences. Under AES-GCM a repeated (key, nonce) pair is not a
/// graceful degradation: it leaks the XOR of the two plaintexts and
/// exposes the GHASH authentication key, which permits forgery. This is
/// therefore safe only when each sequence gets a **fresh key**, which
/// is the design intent — one key per session or per file, as in spec
/// Section 2 — with the salt providing defence in depth rather than the
/// primary guarantee.
///
/// Prefer [`ChunkNonceSequence::random`] over [`ChunkNonceSequence::new`]:
/// `new` exists for deserializing a salt received on the wire or read
/// from a file header, not for picking one.
pub struct ChunkNonceSequence {
    salt: [u8; 4],
    counter: u64,
}

impl ChunkNonceSequence {
    /// Build a sequence from an existing salt — one received from a
    /// peer or read from a file header. To *choose* a salt, use
    /// [`ChunkNonceSequence::random`].
    pub fn new(salt: [u8; 4]) -> Self {
        Self { salt, counter: 0 }
    }

    /// Build a sequence with a freshly sampled random salt.
    ///
    /// # Panics
    ///
    /// Panics if the operating system RNG fails. Deliberate
    /// fail-closed behaviour: the condition is not attacker-controlled,
    /// and a predictable salt combined with a reused key is exactly the
    /// catastrophic case documented on this type.
    pub fn random() -> Self {
        let mut salt = [0u8; 4];
        getrandom::fill(&mut salt).expect("OS RNG failure");
        Self::new(salt)
    }

    /// The salt this sequence is using, to be transmitted alongside the
    /// ciphertext so the receiver can reconstruct the same nonces.
    pub fn salt(&self) -> [u8; 4] {
        self.salt
    }

    /// Returns the next nonce in the sequence. Panics on counter
    /// overflow (2^64 chunks under one key is not a realistic limit
    /// for this protocol's message/file sizes).
    pub fn next(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self
            .counter
            .checked_add(1)
            .expect("nonce counter exhausted");
        nonce
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub fn encrypt(
    alg: AeadAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, aead::Error> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match alg {
        AeadAlgorithm::Aes256Gcm => Aes256Gcm::new(key.into()).encrypt(nonce.into(), payload),
        AeadAlgorithm::ChaCha20Poly1305 => {
            ChaCha20Poly1305::new(key.into()).encrypt(nonce.into(), payload)
        }
    }
}

pub fn decrypt(
    alg: AeadAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, aead::Error> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match alg {
        AeadAlgorithm::Aes256Gcm => Aes256Gcm::new(key.into()).decrypt(nonce.into(), payload),
        AeadAlgorithm::ChaCha20Poly1305 => {
            ChaCha20Poly1305::new(key.into()).decrypt(nonce.into(), payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn nonce_sequence_is_unique_across_many_calls() {
        let mut seq = ChunkNonceSequence::new([0xAA, 0xBB, 0xCC, 0xDD]);
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(seq.next()));
        }
    }

    #[test]
    fn nonce_sequence_embeds_salt_and_increments_counter() {
        let mut seq = ChunkNonceSequence::new([1, 2, 3, 4]);
        let n0 = seq.next();
        let n1 = seq.next();
        assert_eq!(&n0[..4], &[1, 2, 3, 4]);
        assert_eq!(&n1[..4], &[1, 2, 3, 4]);
        assert_eq!(&n0[4..], &0u64.to_be_bytes());
        assert_eq!(&n1[4..], &1u64.to_be_bytes());
    }

    #[test]
    fn random_sequences_start_at_counter_zero_and_carry_their_salt() {
        let mut seq = ChunkNonceSequence::random();
        let salt = seq.salt();
        let first = seq.next();
        assert_eq!(&first[..4], &salt[..]);
        assert_eq!(&first[4..], &0u64.to_be_bytes());
    }

    /// Two independently seeded sequences must not be identical. This
    /// is a smoke test that `random()` samples at all (a hardcoded salt
    /// would fail it), not a statistical test of the RNG.
    #[test]
    fn random_sequences_differ_from_each_other() {
        let salts: HashSet<[u8; 4]> = (0..64).map(|_| ChunkNonceSequence::random().salt()).collect();
        assert!(
            salts.len() > 1,
            "random() must sample a fresh salt each time",
        );
    }

    #[test]
    fn a_sequence_rebuilt_from_a_transmitted_salt_reproduces_the_nonces() {
        let mut sender = ChunkNonceSequence::random();
        let mut receiver = ChunkNonceSequence::new(sender.salt());
        for _ in 0..8 {
            assert_eq!(sender.next(), receiver.next());
        }
    }

    #[test]
    fn aes256gcm_round_trips() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let ct = encrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"aad", b"hello aegis").unwrap();
        let pt = decrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello aegis");
    }

    #[test]
    fn chacha20poly1305_round_trips() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let ct = encrypt(AeadAlgorithm::ChaCha20Poly1305, &key, &nonce, b"aad", b"hello aegis").unwrap();
        let pt = decrypt(AeadAlgorithm::ChaCha20Poly1305, &key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello aegis");
    }

    /// The AAD is authenticated but not encrypted, so nothing about the
    /// ciphertext bytes changes when it does. Every other test in this
    /// module passes the same AAD to encrypt and decrypt, so none of
    /// them would notice if the AAD were dropped on the decrypt path
    /// entirely. This one would.
    #[test]
    fn decrypting_with_a_different_aad_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        for alg in [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::ChaCha20Poly1305] {
            let ct = encrypt(alg, &key, &nonce, b"context-a", b"hello aegis").unwrap();
            assert!(
                decrypt(alg, &key, &nonce, b"context-b", &ct).is_err(),
                "{alg:?}: mismatched AAD must fail authentication",
            );
            // Absent AAD must fail too — otherwise an attacker could
            // simply strip the binding rather than substitute it.
            assert!(
                decrypt(alg, &key, &nonce, b"", &ct).is_err(),
                "{alg:?}: stripped AAD must fail authentication",
            );
            // Sanity: the matching AAD still works, so the assertions
            // above are about the AAD and not a broken fixture.
            assert_eq!(
                decrypt(alg, &key, &nonce, b"context-a", &ct).unwrap(),
                b"hello aegis",
            );
        }
    }

    /// The mirror case: AAD supplied at decrypt where none was
    /// supplied at encrypt.
    #[test]
    fn decrypting_with_added_aad_fails_when_none_was_authenticated() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let ct = encrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"", b"hello aegis").unwrap();
        assert!(decrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"aad", &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let mut ct = encrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"aad", b"hello aegis").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(decrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"aad", &ct).is_err());
    }

    /// NIST CAVS vector from `gcmEncryptExtIV256.rsp`, first empty-plaintext
    /// entry, as vendored in the `aes-gcm` crate's own test suite
    /// (RustCrypto/AEADs, aes-gcm/tests/aes256gcm.rs). Verifies our wrapper's
    /// plumbing against an official KAT per spec Section 9.1.
    #[test]
    fn aes256gcm_official_kat_empty_plaintext() {
        let key: [u8; 32] =
            hex::decode("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4")
                .unwrap()[..32]
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = hex::decode("516c33929df5a3284ff463d7").unwrap()[..12]
            .try_into()
            .unwrap();
        let expected_tag = hex::decode("bdc1ac884d332457a1d2664f168c76f0").unwrap();

        let ct = encrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"", b"").unwrap();
        assert_eq!(ct, expected_tag, "ciphertext for empty plaintext is just the 16-byte tag");
    }

    /// RFC 8439 Section 2.8.2 worked example — the canonical
    /// ChaCha20-Poly1305 AEAD test vector, transcribed directly from the
    /// RFC text. Verifies our wrapper's plumbing against an official KAT
    /// per spec Section 9.1.
    #[test]
    fn chacha20poly1305_official_kat_rfc8439() {
        let key: [u8; 32] = hex::decode(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )
        .unwrap()[..32]
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex::decode("070000004041424344454647").unwrap()[..12]
            .try_into()
            .unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ciphertext_and_tag = hex::decode(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2",
            "a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b",
            "1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58",
            "fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b",
            "6116",
            "1ae10b594f09e26a7e902ecbd0600691",
        ))
        .unwrap();

        let ct = encrypt(
            AeadAlgorithm::ChaCha20Poly1305,
            &key,
            &nonce,
            &aad,
            plaintext,
        )
        .unwrap();
        assert_eq!(ct, expected_ciphertext_and_tag);
    }
}
