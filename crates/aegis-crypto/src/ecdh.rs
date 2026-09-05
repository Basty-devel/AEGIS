//! brainpoolP512r1 ECDH. See AEGIS.Plan.V0.2.md Section 2.
//!
//! Uses `bp512-nestler` (see this crate's Cargo.toml and the workspace
//! root's `[patch.crates-io]` block) since no brainpool512r1
//! implementation exists in the mainline RustCrypto ecosystem as of
//! this writing. Domain parameters: RFC 5639 Section 3.7.

use bp512_nestler::BrainpoolP512r1;
use elliptic_curve::{PublicKey, SecretKey};

pub struct Brainpool512SecretKey(SecretKey<BrainpoolP512r1>);

impl Brainpool512SecretKey {
    pub fn generate() -> Self {
        loop {
            let mut bytes = elliptic_curve::FieldBytes::<BrainpoolP512r1>::default();
            getrandom::fill(&mut bytes).expect("OS RNG failure");
            if let Ok(secret) = SecretKey::<BrainpoolP512r1>::from_bytes(&bytes) {
                return Self(secret);
            }
            // Rejection sampling: retry on the astronomically rare case
            // the raw bytes aren't a valid nonzero scalar below the
            // curve order.
        }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.public_key().to_sec1_bytes().to_vec()
    }
}

pub fn brainpool512_diffie_hellman(
    secret: &Brainpool512SecretKey,
    peer_public_bytes: &[u8],
) -> [u8; 64] {
    let peer_public = PublicKey::<BrainpoolP512r1>::from_sec1_bytes(peer_public_bytes)
        .expect("invalid peer public key encoding");
    let shared = secret.0.diffie_hellman(&peer_public);
    let mut out = [0u8; 64];
    out.copy_from_slice(shared.raw_secret_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_shared_secret() {
        let alice = Brainpool512SecretKey::generate();
        let bob = Brainpool512SecretKey::generate();

        let alice_shared = brainpool512_diffie_hellman(&alice, &bob.public_key_bytes());
        let bob_shared = brainpool512_diffie_hellman(&bob, &alice.public_key_bytes());

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn different_peers_give_different_shared_secrets() {
        let alice = Brainpool512SecretKey::generate();
        let bob = Brainpool512SecretKey::generate();
        let carol = Brainpool512SecretKey::generate();

        let alice_bob = brainpool512_diffie_hellman(&alice, &bob.public_key_bytes());
        let alice_carol = brainpool512_diffie_hellman(&alice, &carol.public_key_bytes());

        assert_ne!(alice_bob, alice_carol);
    }
}
