//! Hybrid ML-KEM-1024 + brainpool512r1 KEM combiner. See
//! AEGIS.Plan.V0.2.md Section 2.
//!
//! Construction: `K = HKDF-SHA512(SS_brainpool512r1 || SS_ML-KEM-1024,
//! info = domain_label || protocol_version || pubkey_A || pubkey_B)`.
//! Reference: NIST SP 800-56C (concatenation KDF combiner).

use crate::ecdh::{brainpool512_diffie_hellman, Brainpool512SecretKey};
use crate::kdf::derive_key;
use crate::kem::{ml_kem_decapsulate, ml_kem_encapsulate, MlKem1024KeyPair};

const DOMAIN_LABEL: &[u8] = b"AegisPQC-v1-HybridKEM";

pub struct HybridPublicKeys {
    pub brainpool512: Vec<u8>,
    pub ml_kem1024_ek: Vec<u8>,
}

pub struct HybridCiphertext {
    pub brainpool512_ephemeral_public: Vec<u8>,
    pub ml_kem1024_ciphertext: Vec<u8>,
}

/// Encapsulate to `peer_keys`, generating a fresh ephemeral
/// brainpool512r1 keypair for this exchange. Returns the ciphertext
/// bundle to send and the resulting 32-byte shared key.
pub fn hybrid_kem_encapsulate(
    protocol_version: u8,
    peer_keys: &HybridPublicKeys,
) -> (HybridCiphertext, [u8; 32]) {
    let ephemeral_brainpool = Brainpool512SecretKey::generate();
    let brainpool_shared =
        brainpool512_diffie_hellman(&ephemeral_brainpool, &peer_keys.brainpool512);
    let (ml_kem_ciphertext, ml_kem_shared) = ml_kem_encapsulate(&peer_keys.ml_kem1024_ek);

    let mut ikm = Vec::with_capacity(brainpool_shared.len() + ml_kem_shared.len());
    ikm.extend_from_slice(&brainpool_shared);
    ikm.extend_from_slice(&ml_kem_shared);

    let mut key = [0u8; 32];
    derive_key(
        &ikm,
        DOMAIN_LABEL,
        protocol_version,
        &ephemeral_brainpool.public_key_bytes(),
        &peer_keys.brainpool512,
        &mut key,
    )
    .expect("HKDF output length is valid");

    (
        HybridCiphertext {
            brainpool512_ephemeral_public: ephemeral_brainpool.public_key_bytes(),
            ml_kem1024_ciphertext: ml_kem_ciphertext,
        },
        key,
    )
}

/// Decapsulate a bundle produced by [`hybrid_kem_encapsulate`] using
/// our own long-term keys.
pub fn hybrid_kem_decapsulate(
    protocol_version: u8,
    our_brainpool_secret: &Brainpool512SecretKey,
    our_ml_kem: &MlKem1024KeyPair,
    our_public_keys: &HybridPublicKeys,
    ciphertext: &HybridCiphertext,
) -> [u8; 32] {
    let brainpool_shared = brainpool512_diffie_hellman(
        our_brainpool_secret,
        &ciphertext.brainpool512_ephemeral_public,
    );
    let ml_kem_shared = ml_kem_decapsulate(our_ml_kem, &ciphertext.ml_kem1024_ciphertext);

    let mut ikm = Vec::with_capacity(brainpool_shared.len() + ml_kem_shared.len());
    ikm.extend_from_slice(&brainpool_shared);
    ikm.extend_from_slice(&ml_kem_shared);

    let mut key = [0u8; 32];
    derive_key(
        &ikm,
        DOMAIN_LABEL,
        protocol_version,
        &ciphertext.brainpool512_ephemeral_public,
        &our_public_keys.brainpool512,
        &mut key,
    )
    .expect("HKDF output length is valid");

    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdh::Brainpool512SecretKey;
    use crate::kem::MlKem1024KeyPair;

    fn keys_for(brainpool: &Brainpool512SecretKey, ml_kem: &MlKem1024KeyPair) -> HybridPublicKeys {
        HybridPublicKeys {
            brainpool512: brainpool.public_key_bytes(),
            ml_kem1024_ek: ml_kem.encapsulation_key_bytes(),
        }
    }

    #[test]
    fn both_sides_derive_the_same_hybrid_key() {
        let alice_brainpool = Brainpool512SecretKey::generate();
        let alice_ml_kem = MlKem1024KeyPair::generate();
        let alice_public = keys_for(&alice_brainpool, &alice_ml_kem);

        let (ciphertext, sender_key) = hybrid_kem_encapsulate(1, &alice_public);
        let receiver_key = hybrid_kem_decapsulate(
            1,
            &alice_brainpool,
            &alice_ml_kem,
            &alice_public,
            &ciphertext,
        );

        assert_eq!(sender_key, receiver_key);
    }

    #[test]
    fn different_protocol_versions_derive_different_keys() {
        let brainpool = Brainpool512SecretKey::generate();
        let ml_kem = MlKem1024KeyPair::generate();
        let public = keys_for(&brainpool, &ml_kem);

        let (ciphertext_v1, key_v1) = hybrid_kem_encapsulate(1, &public);
        let key_v1_decap = hybrid_kem_decapsulate(1, &brainpool, &ml_kem, &public, &ciphertext_v1);
        assert_eq!(key_v1, key_v1_decap);

        // Re-deriving with a mismatched version byte on the decapsulating
        // side must NOT produce the same key as the sender used — proves
        // the version byte is actually bound into the KDF info, not
        // decorative.
        let key_wrong_version =
            hybrid_kem_decapsulate(2, &brainpool, &ml_kem, &public, &ciphertext_v1);
        assert_ne!(key_v1, key_wrong_version);
    }
}
