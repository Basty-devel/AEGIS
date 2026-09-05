//! Ed25519 + ML-DSA-87 dual-signature wrapper (NIST FIPS 204). See
//! AEGIS.Plan.V0.2.md Section 2. A signature is only considered valid
//! if BOTH the Ed25519 and ML-DSA-87 components verify — this is what
//! "ML-DSA-87 paired with Ed25519" means in the spec.

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey, Verifier as _, VerifyingKey as Ed25519VerifyingKey};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, SigningKey as MlDsa87SigningKey, VerifyingKey as MlDsa87VerifyingKey};
use signature::Keypair;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A paired Ed25519 + ML-DSA-87 signing key.
///
/// Both component signing keys wipe their own secret material on drop:
///
/// - `ed25519_dalek::SigningKey` implements `Drop` + `ZeroizeOnDrop`
///   behind its `zeroize` feature, which is one of that crate's
///   *default* features (verified in ed25519-dalek 3.0.0's `Cargo.toml`
///   and `src/signing.rs`).
/// - `ml_dsa::SigningKey` implements `Drop` + `ZeroizeOnDrop` behind
///   ml-dsa's `zeroize` feature, which is **not** on by default —
///   without it, `SigningKey::drop` is an empty function and both the
///   seed and the expanded key survive the drop. This crate enables the
///   feature explicitly in `Cargo.toml`; see the comment there.
///
/// The `ZeroizeOnDrop` derive delegates to those two `Drop` impls (it
/// adds no wiping of its own) and records the guarantee at this type,
/// so a future field that does *not* zeroize itself becomes a compile
/// error rather than a silent leak.
#[derive(ZeroizeOnDrop)]
pub struct DualKeyPair {
    ed25519: Ed25519SigningKey,
    ml_dsa87: MlDsa87SigningKey<MlDsa87>,
}

/// A dual signature. Contains no secret material — signatures are
/// public values — so it is deliberately not zeroized.
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
    ///
    /// Each seed fully determines its signing key, so both are wiped
    /// before this function returns.
    ///
    /// # Panics
    ///
    /// Panics if the operating system RNG fails. Deliberate fail-closed
    /// behaviour: the condition is not attacker-controlled (no wire
    /// data reaches it), and deriving a long-term identity key from
    /// unknown entropy would be far worse than aborting.
    pub fn generate() -> Self {
        let mut ed25519_seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(ed25519_seed.as_mut()).expect("OS RNG failure");
        let ed25519 = Ed25519SigningKey::from_bytes(&ed25519_seed);

        // Built directly as an `Array` rather than via
        // `[u8; 32].into()`, which would leave an un-zeroized copy of
        // the ML-DSA seed on the stack.
        let mut ml_dsa87_seed = ml_dsa::Seed::default();
        getrandom::fill(ml_dsa87_seed.as_mut_slice()).expect("OS RNG failure");
        let ml_dsa87 = MlDsa87SigningKey::<MlDsa87>::from_seed(&ml_dsa87_seed);
        ml_dsa87_seed.as_mut_slice().zeroize();

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

    /// C2 regression guard — see the equivalent test in `kem.rs`. This
    /// one additionally pins both component key types, since ml-dsa's
    /// `zeroize` feature is not on by default and its absence would
    /// otherwise be invisible.
    #[test]
    fn dual_keypair_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<DualKeyPair>();
        assert_zeroize_on_drop::<Ed25519SigningKey>();
        assert_zeroize_on_drop::<MlDsa87SigningKey<MlDsa87>>();
    }

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

    /// The mirror of the test above, and the one that matters most:
    /// every other test in this module would still pass if
    /// `ml_dsa87_ok` were hardcoded `true`, because the Ed25519 leg
    /// alone catches their failure modes. This one leaves the Ed25519
    /// signature completely valid, so it fails only if the post-quantum
    /// half genuinely verifies.
    #[test]
    fn tampered_ml_dsa87_component_fails_even_though_ed25519_is_valid() {
        let keypair = DualKeyPair::generate();
        let mut sig = keypair.sign(b"hello aegis");

        // Sanity: the untampered pair verifies, so a later failure is
        // attributable to the tamper and not to a broken fixture.
        assert!(verify_dual(
            &keypair.ed25519_public_bytes(),
            &keypair.ml_dsa87_public_bytes(),
            b"hello aegis",
            &sig,
        ));

        sig.ml_dsa87[0] ^= 0xFF;
        assert!(
            !verify_dual(
                &keypair.ed25519_public_bytes(),
                &keypair.ml_dsa87_public_bytes(),
                b"hello aegis",
                &sig,
            ),
            "a tampered ML-DSA-87 signature must be rejected even when Ed25519 verifies",
        );
    }

    /// Same again, tampering deeper into the signature body rather than
    /// its first byte (which lands in the commitment hash `c~`, a
    /// different rejection path from the response vector `z`).
    #[test]
    fn tampered_ml_dsa87_signature_body_fails() {
        let keypair = DualKeyPair::generate();
        let mut sig = keypair.sign(b"hello aegis");
        let midpoint = sig.ml_dsa87.len() / 2;
        sig.ml_dsa87[midpoint] ^= 0x01;
        assert!(!verify_dual(
            &keypair.ed25519_public_bytes(),
            &keypair.ml_dsa87_public_bytes(),
            b"hello aegis",
            &sig,
        ));
    }

    /// A different signer's ML-DSA-87 key with a valid Ed25519 leg:
    /// proves the ML-DSA public key is actually consulted, not ignored.
    #[test]
    fn wrong_ml_dsa87_public_key_fails_even_though_ed25519_is_valid() {
        let keypair = DualKeyPair::generate();
        let other = DualKeyPair::generate();
        let sig = keypair.sign(b"hello aegis");
        assert!(!verify_dual(
            &keypair.ed25519_public_bytes(),
            &other.ml_dsa87_public_bytes(),
            b"hello aegis",
            &sig,
        ));
    }

    /// Exercises the `EncodedVerifyingKey::try_from` size guard, which
    /// no previous test reached. Attacker-controlled length: must
    /// return `false`, never panic.
    #[test]
    fn wrong_length_ml_dsa87_public_key_is_rejected_without_panicking() {
        let keypair = DualKeyPair::generate();
        let sig = keypair.sign(b"hello aegis");
        let correct = keypair.ml_dsa87_public_bytes();

        for malformed in [
            Vec::new(),
            vec![0u8; 1],
            correct[..correct.len() - 1].to_vec(),
            {
                let mut too_long = correct.clone();
                too_long.push(0);
                too_long
            },
        ] {
            assert!(
                !verify_dual(
                    &keypair.ed25519_public_bytes(),
                    &malformed,
                    b"hello aegis",
                    &sig,
                ),
                "wrong-length ML-DSA-87 public key ({} bytes) must be rejected",
                malformed.len(),
            );
        }
    }

    /// Exercises the `EncodedSignature::try_from` size guard, likewise
    /// previously unreached.
    #[test]
    fn wrong_length_ml_dsa87_signature_is_rejected_without_panicking() {
        let keypair = DualKeyPair::generate();
        let sig = keypair.sign(b"hello aegis");

        for malformed in [
            Vec::new(),
            vec![0u8; 1],
            sig.ml_dsa87[..sig.ml_dsa87.len() - 1].to_vec(),
            {
                let mut too_long = sig.ml_dsa87.clone();
                too_long.push(0);
                too_long
            },
        ] {
            let len = malformed.len();
            let tampered = DualSignature {
                ed25519: sig.ed25519,
                ml_dsa87: malformed,
            };
            assert!(
                !verify_dual(
                    &keypair.ed25519_public_bytes(),
                    &keypair.ml_dsa87_public_bytes(),
                    b"hello aegis",
                    &tampered,
                ),
                "wrong-length ML-DSA-87 signature ({len} bytes) must be rejected",
            );
        }
    }
}
