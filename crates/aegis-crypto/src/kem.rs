//! ML-KEM-1024 wrapper (NIST FIPS 203). See AEGIS.Plan.V0.2.md Section 2.
//!
//! Uses `encapsulate_deterministic` (fed with our own OS-random 32-byte
//! value via `getrandom`) rather than the crate's `Encapsulate` trait,
//! which otherwise needs a `rand_core::CryptoRng` implementation we'd
//! have to adapt `getrandom` into ourselves — this achieves the same
//! thing without an extra adapter type.

use crate::error::CryptoError;
use ml_kem::{
    array::Array, Ciphertext, Decapsulate, EncapsulationKey, FromSeed, Key, KeyExport, MlKem1024,
    B32,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Byte length of an ML-KEM-1024 encapsulation key (FIPS 203 Table 3).
pub const ML_KEM_1024_ENCAPSULATION_KEY_LEN: usize = 1568;

/// Byte length of an ML-KEM-1024 ciphertext (FIPS 203 Table 3).
pub const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1568;

/// Byte length of an ML-KEM-1024 shared secret (FIPS 203 Table 3).
pub const ML_KEM_1024_SHARED_SECRET_LEN: usize = 32;

/// An ML-KEM-1024 keypair.
///
/// `ml_kem::DecapsulationKey` implements `Drop` + `ZeroizeOnDrop` only
/// when the `ml-kem` crate's non-default `zeroize` feature is enabled —
/// verified by source inspection of ml-kem 0.3.2
/// (`src/decapsulation_key.rs`), and enabled explicitly in this crate's
/// `Cargo.toml`. The `ZeroizeOnDrop` derive here delegates to that
/// (the field's own `Drop` does the wiping) and additionally documents
/// the guarantee at this type. The encapsulation key is public
/// material and is skipped.
#[derive(ZeroizeOnDrop)]
pub struct MlKem1024KeyPair {
    decapsulation_key: ml_kem::DecapsulationKey<MlKem1024>,
    #[zeroize(skip)]
    encapsulation_key: EncapsulationKey<MlKem1024>,
}

impl MlKem1024KeyPair {
    /// Generate a fresh ML-KEM-1024 keypair from OS randomness.
    ///
    /// # Panics
    ///
    /// Panics if the operating system RNG fails. Deliberate fail-closed
    /// behaviour: the condition is not attacker-controlled (no wire
    /// data reaches it), and generating a keypair from unknown entropy
    /// would be strictly worse than aborting.
    pub fn generate() -> Self {
        // The seed is built directly in its final `Array` form and
        // wiped afterwards; going via `[u8; 64].into()` would leave an
        // un-zeroized copy of the full ML-KEM seed (which determines
        // the decapsulation key) on the stack.
        let mut seed = ml_kem::Seed::default();
        getrandom::fill(seed.as_mut_slice()).expect("OS RNG failure");
        let (decapsulation_key, encapsulation_key) = MlKem1024::from_seed(&seed);
        seed.as_mut_slice().zeroize();
        Self {
            decapsulation_key,
            encapsulation_key,
        }
    }

    pub fn encapsulation_key_bytes(&self) -> Vec<u8> {
        self.encapsulation_key.to_bytes().to_vec()
    }
}

/// Encapsulate to the ML-KEM-1024 encapsulation key encoded in
/// `encapsulation_key_bytes`, returning the ciphertext to send and the
/// resulting shared secret.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidEncapsulationKeyLength`] if the key is
/// not exactly [`ML_KEM_1024_ENCAPSULATION_KEY_LEN`] bytes, or
/// [`CryptoError::InvalidEncapsulationKey`] if it fails FIPS 203's
/// modulus check. Both are reachable directly from peer-supplied bytes,
/// so neither may panic.
///
/// # Panics
///
/// Panics if the operating system RNG fails while sampling the
/// encapsulation randomness `m`. Deliberate fail-closed behaviour: `m`
/// fully determines the shared secret, so proceeding without real
/// entropy would silently produce a predictable key.
pub fn ml_kem_encapsulate(
    encapsulation_key_bytes: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; ML_KEM_1024_SHARED_SECRET_LEN]>), CryptoError> {
    let key_array: Key<EncapsulationKey<MlKem1024>> = Array::try_from(encapsulation_key_bytes)
        .map_err(|_| CryptoError::InvalidEncapsulationKeyLength {
            expected: ML_KEM_1024_ENCAPSULATION_KEY_LEN,
            actual: encapsulation_key_bytes.len(),
        })?;
    let ek = EncapsulationKey::<MlKem1024>::new(&key_array)
        .map_err(|_| CryptoError::InvalidEncapsulationKey)?;

    // `m` is the encapsulation randomness: it fully determines the
    // shared secret, so it is wiped as soon as encapsulation is done.
    let mut m = B32::default();
    getrandom::fill(m.as_mut_slice()).expect("OS RNG failure");

    let (ciphertext, mut shared_secret) = ek.encapsulate_deterministic(&m);
    m.as_mut_slice().zeroize();

    // Copied out and the original wiped explicitly. `ml-kem` returns the
    // shared secret as a `hybrid_array::Array`, which only zeroizes on
    // drop when hybrid-array's own `zeroize` feature happens to be
    // enabled somewhere in the build graph — a Cargo feature-unification
    // accident is not a basis for a security property.
    let mut out = Zeroizing::new([0u8; ML_KEM_1024_SHARED_SECRET_LEN]);
    out.copy_from_slice(shared_secret.as_slice());
    shared_secret.as_mut_slice().zeroize();

    Ok((ciphertext.to_vec(), out))
}

/// Decapsulate an ML-KEM-1024 ciphertext with `keypair`'s decapsulation
/// key.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidCiphertextLength`] if `ciphertext` is
/// not exactly [`ML_KEM_1024_CIPHERTEXT_LEN`] bytes. A *well-formed but
/// wrong* ciphertext is not an error: FIPS 203 mandates implicit
/// rejection, which returns an unpredictable shared secret rather than
/// signalling failure, and `ml-kem` implements that internally.
pub fn ml_kem_decapsulate(
    keypair: &MlKem1024KeyPair,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; ML_KEM_1024_SHARED_SECRET_LEN]>, CryptoError> {
    let ct: Ciphertext<MlKem1024> =
        Array::try_from(ciphertext).map_err(|_| CryptoError::InvalidCiphertextLength {
            expected: ML_KEM_1024_CIPHERTEXT_LEN,
            actual: ciphertext.len(),
        })?;
    // Same explicit copy-and-wipe as `ml_kem_encapsulate`.
    let mut shared_secret = keypair.decapsulation_key.decapsulate(&ct);
    let mut out = Zeroizing::new([0u8; ML_KEM_1024_SHARED_SECRET_LEN]);
    out.copy_from_slice(shared_secret.as_slice());
    shared_secret.as_mut_slice().zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C2 regression guard. Zeroization cannot be observed from safe
    /// Rust (the crate denies `unsafe`, so freed memory cannot be
    /// inspected), but the *type-level* guarantee can be asserted at
    /// compile time. If ml-kem's non-default `zeroize` feature is ever
    /// dropped from Cargo.toml, `DecapsulationKey` stops implementing
    /// `ZeroizeOnDrop`, the derive on `MlKem1024KeyPair` stops
    /// compiling, and this test fails to build rather than silently
    /// leaking key material.
    #[test]
    fn keypair_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<MlKem1024KeyPair>();
        assert_zeroize_on_drop::<ml_kem::DecapsulationKey<MlKem1024>>();
    }

    #[test]
    fn shared_secrets_are_returned_wrapped_for_zeroization() {
        fn assert_zeroizing<T: zeroize::Zeroize>(_: &Zeroizing<T>) {}
        let keypair = MlKem1024KeyPair::generate();
        let (ciphertext, secret) = ml_kem_encapsulate(&keypair.encapsulation_key_bytes()).unwrap();
        assert_zeroizing(&secret);
        assert_zeroizing(&ml_kem_decapsulate(&keypair, &ciphertext).unwrap());
    }

    #[test]
    fn encapsulate_then_decapsulate_recovers_shared_secret() {
        let keypair = MlKem1024KeyPair::generate();
        let (ciphertext, sender_secret) =
            ml_kem_encapsulate(&keypair.encapsulation_key_bytes()).unwrap();
        let receiver_secret = ml_kem_decapsulate(&keypair, &ciphertext).unwrap();
        assert_eq!(*sender_secret, *receiver_secret);
    }

    #[test]
    fn malformed_encapsulation_key_is_rejected_without_panicking() {
        for malformed in [&b""[..], &b"short"[..], &[0u8; 1567][..], &[0u8; 1569][..]] {
            assert_eq!(
                ml_kem_encapsulate(malformed).unwrap_err(),
                CryptoError::InvalidEncapsulationKeyLength {
                    expected: ML_KEM_1024_ENCAPSULATION_KEY_LEN,
                    actual: malformed.len(),
                },
            );
        }
    }

    #[test]
    fn malformed_ciphertext_is_rejected_without_panicking() {
        let keypair = MlKem1024KeyPair::generate();
        for malformed in [&b""[..], &b"short"[..], &[0u8; 1567][..], &[0u8; 1569][..]] {
            assert_eq!(
                ml_kem_decapsulate(&keypair, malformed).unwrap_err(),
                CryptoError::InvalidCiphertextLength {
                    expected: ML_KEM_1024_CIPHERTEXT_LEN,
                    actual: malformed.len(),
                },
            );
        }
    }

    #[test]
    fn declared_wire_lengths_match_the_real_encodings() {
        let keypair = MlKem1024KeyPair::generate();
        assert_eq!(
            keypair.encapsulation_key_bytes().len(),
            ML_KEM_1024_ENCAPSULATION_KEY_LEN,
        );
        let (ciphertext, _) = ml_kem_encapsulate(&keypair.encapsulation_key_bytes()).unwrap();
        assert_eq!(ciphertext.len(), ML_KEM_1024_CIPHERTEXT_LEN);
    }

    #[test]
    fn different_keypairs_produce_different_shared_secrets() {
        let a = MlKem1024KeyPair::generate();
        let b = MlKem1024KeyPair::generate();
        let (_, secret_a) = ml_kem_encapsulate(&a.encapsulation_key_bytes()).unwrap();
        let (_, secret_b) = ml_kem_encapsulate(&b.encapsulation_key_bytes()).unwrap();
        assert_ne!(*secret_a, *secret_b);
    }
}
