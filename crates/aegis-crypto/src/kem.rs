//! ML-KEM-1024 wrapper (NIST FIPS 203). See AEGIS.Plan.V0.2.md Section 2.
//!
//! Uses `encapsulate_deterministic` (fed with our own OS-random 32-byte
//! value via `getrandom`) rather than the crate's `Encapsulate` trait,
//! which otherwise needs a `rand_core::CryptoRng` implementation we'd
//! have to adapt `getrandom` into ourselves — this achieves the same
//! thing without an extra adapter type.

use ml_kem::{
    array::Array, Ciphertext, Decapsulate, EncapsulationKey, FromSeed, Key, KeyExport, MlKem1024,
    B32,
};

pub struct MlKem1024KeyPair {
    decapsulation_key: ml_kem::DecapsulationKey<MlKem1024>,
    encapsulation_key: EncapsulationKey<MlKem1024>,
}

impl MlKem1024KeyPair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 64];
        getrandom::fill(&mut seed).expect("OS RNG failure");
        let (decapsulation_key, encapsulation_key) = MlKem1024::from_seed(&seed.into());
        Self {
            decapsulation_key,
            encapsulation_key,
        }
    }

    pub fn encapsulation_key_bytes(&self) -> Vec<u8> {
        self.encapsulation_key.to_bytes().to_vec()
    }
}

pub fn ml_kem_encapsulate(encapsulation_key_bytes: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let key_array: Key<EncapsulationKey<MlKem1024>> =
        Array::try_from(encapsulation_key_bytes).expect("wrong encapsulation key length");
    let ek = EncapsulationKey::<MlKem1024>::new(&key_array).expect("invalid encapsulation key");

    let mut randomness = [0u8; 32];
    getrandom::fill(&mut randomness).expect("OS RNG failure");
    let m: B32 = randomness.into();

    let (ciphertext, shared_secret) = ek.encapsulate_deterministic(&m);
    (ciphertext.to_vec(), shared_secret.into())
}

pub fn ml_kem_decapsulate(keypair: &MlKem1024KeyPair, ciphertext: &[u8]) -> [u8; 32] {
    let ct: Ciphertext<MlKem1024> =
        Array::try_from(ciphertext).expect("wrong ciphertext length");
    keypair.decapsulation_key.decapsulate(&ct).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_then_decapsulate_recovers_shared_secret() {
        let keypair = MlKem1024KeyPair::generate();
        let (ciphertext, sender_secret) = ml_kem_encapsulate(&keypair.encapsulation_key_bytes());
        let receiver_secret = ml_kem_decapsulate(&keypair, &ciphertext);
        assert_eq!(sender_secret, receiver_secret);
    }

    #[test]
    fn different_keypairs_produce_different_shared_secrets() {
        let a = MlKem1024KeyPair::generate();
        let b = MlKem1024KeyPair::generate();
        let (_, secret_a) = ml_kem_encapsulate(&a.encapsulation_key_bytes());
        let (_, secret_b) = ml_kem_encapsulate(&b.encapsulation_key_bytes());
        assert_ne!(secret_a, secret_b);
    }
}
