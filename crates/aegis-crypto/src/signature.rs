//! Ed25519 + ML-DSA-87 dual-signature wrapper (NIST FIPS 204). See
//! AEGIS.Plan.V0.2.md Section 2. A signature is only considered valid
//! if BOTH the Ed25519 and ML-DSA-87 components verify — this is what
//! "ML-DSA-87 paired with Ed25519" means in the spec.

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey, Verifier as _, VerifyingKey as Ed25519VerifyingKey};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, SigningKey as MlDsa87SigningKey, VerifyingKey as MlDsa87VerifyingKey};
use signature::Keypair;

pub struct DualKeyPair {
    ed25519: Ed25519SigningKey,
    ml_dsa87: MlDsa87SigningKey<MlDsa87>,
}

pub struct DualSignature {
    pub ed25519: [u8; 64],
    pub ml_dsa87: Vec<u8>,
}

impl DualKeyPair {
    /// Both component keys are generated from independent
    /// securely-random 32-byte seeds via `getrandom` — the same
    /// `from_seed` construction the ML-DSA-87 ACVP KAT (Task 6, Step 5)
    /// verifies deterministically, just with real OS randomness here
    /// instead of a fixed test seed.
    pub fn generate() -> Self {
        let mut ed25519_seed = [0u8; 32];
        getrandom::fill(&mut ed25519_seed).expect("OS RNG failure");
        let ed25519 = Ed25519SigningKey::from_bytes(&ed25519_seed);

        let mut ml_dsa87_seed = [0u8; 32];
        getrandom::fill(&mut ml_dsa87_seed).expect("OS RNG failure");
        let ml_dsa87 = MlDsa87SigningKey::<MlDsa87>::from_seed(&ml_dsa87_seed.into());

        Self { ed25519, ml_dsa87 }
    }

    pub fn ed25519_public_bytes(&self) -> [u8; 32] {
        self.ed25519.verifying_key().to_bytes()
    }

    pub fn ml_dsa87_public_bytes(&self) -> Vec<u8> {
        self.ml_dsa87.verifying_key().encode().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> DualSignature {
        let ed25519 = self.ed25519.sign(message).to_bytes();
        let ml_dsa87 = self.ml_dsa87.sign(message).encode().to_vec();
        DualSignature { ed25519, ml_dsa87 }
    }
}

pub fn verify_dual(
    ed25519_pub: &[u8; 32],
    ml_dsa87_pub: &[u8],
    message: &[u8],
    sig: &DualSignature,
) -> bool {
    let ed25519_ok = Ed25519VerifyingKey::from_bytes(ed25519_pub)
        .ok()
        .and_then(|vk| {
            let sig = ed25519_dalek::Signature::from_bytes(&sig.ed25519);
            vk.verify(message, &sig).ok()
        })
        .is_some();

    // ML-DSA-87's `decode` takes an already-correctly-sized encoded key/
    // signature and is infallible; the fallible part is the initial
    // `try_from` size check on attacker-controlled byte lengths — same
    // two-step shape the crate's own ACVP test harness uses (Task 6,
    // Step 5).
    let ml_dsa87_ok = EncodedVerifyingKey::<MlDsa87>::try_from(ml_dsa87_pub)
        .ok()
        .and_then(|encoded_vk| {
            let vk = MlDsa87VerifyingKey::decode(&encoded_vk);
            let encoded_sig = EncodedSignature::<MlDsa87>::try_from(sig.ml_dsa87.as_slice()).ok()?;
            let signature = ml_dsa::Signature::<MlDsa87>::decode(&encoded_sig)?;
            vk.verify(message, &signature).ok()
        })
        .is_some();

    ed25519_ok && ml_dsa87_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_dual_signature_verifies() {
        let keypair = DualKeyPair::generate();
        let sig = keypair.sign(b"hello aegis");
        assert!(verify_dual(
            &keypair.ed25519_public_bytes(),
            &keypair.ml_dsa87_public_bytes(),
            b"hello aegis",
            &sig,
        ));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let keypair = DualKeyPair::generate();
        let sig = keypair.sign(b"hello aegis");
        assert!(!verify_dual(
            &keypair.ed25519_public_bytes(),
            &keypair.ml_dsa87_public_bytes(),
            b"goodbye aegis",
            &sig,
        ));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let keypair = DualKeyPair::generate();
        let other = DualKeyPair::generate();
        let sig = keypair.sign(b"hello aegis");
        assert!(!verify_dual(
            &other.ed25519_public_bytes(),
            &other.ml_dsa87_public_bytes(),
            b"hello aegis",
            &sig,
        ));
    }

    #[test]
    fn tampered_ed25519_component_fails_even_if_ml_dsa87_is_valid() {
        let keypair = DualKeyPair::generate();
        let mut sig = keypair.sign(b"hello aegis");
        sig.ed25519[0] ^= 0xFF;
        assert!(!verify_dual(
            &keypair.ed25519_public_bytes(),
            &keypair.ml_dsa87_public_bytes(),
            b"hello aegis",
            &sig,
        ));
    }
}
