//! Hybrid cryptographic primitives: ML-KEM-1024 + brainpool512r1 KEM
//! combiner, ML-DSA-87 + Ed25519 signatures, AEAD, Argon2id, HKDF-SHA512,
//! and memory zeroization.
//!
//! See `AEGIS.Plan.V0.2.md` Sections 2 and 9.1 (cryptographic ground
//! rules — no construction here may deviate from a cited published
//! reference).
//!
//! # Memory zeroization — what is and is not guaranteed
//!
//! Spec Section 2 requires ephemeral private keys and shared secrets to
//! be wiped after use. Concretely, in this crate:
//!
//! - Every function that returns a shared secret returns it inside
//!   [`zeroize::Zeroizing`], so it is wiped when the caller drops it:
//!   [`ecdh::brainpool512_diffie_hellman`], [`kem::ml_kem_encapsulate`],
//!   [`kem::ml_kem_decapsulate`], [`hybrid::hybrid_kem_encapsulate`],
//!   and [`hybrid::hybrid_kem_decapsulate`].
//! - Intermediate secrets are wiped before the function returns: the
//!   ECDH rejection-sampling candidates, the ML-KEM key seed and
//!   encapsulation randomness, the two signing-key seeds, and the
//!   combiner's concatenated IKM.
//! - Long-lived key types wipe themselves on drop:
//!   [`ecdh::Brainpool512SecretKey`] (via `elliptic_curve::SecretKey`),
//!   [`kem::MlKem1024KeyPair`], and [`signature::DualKeyPair`]. The
//!   latter two required enabling the non-default `zeroize` feature of
//!   `ml-kem` and `ml-dsa`; see this crate's `Cargo.toml`.
//!
//! What this does **not** guarantee, and no pure-Rust crate can: that
//! the operating system never copied a secret elsewhere first. Values
//! moved on the stack, spilled to registers, paged to swap, or captured
//! in a core dump are outside `zeroize`'s reach. Zeroization narrows
//! the window; it does not close it.
//!
//! # Panics
//!
//! Nothing in this crate panics on data an attacker controls. Malformed
//! peer public keys, encapsulation keys, ciphertexts, signatures, and
//! signature-verification keys all return [`CryptoError`] or `false`.
//! The only panics are fail-closed reactions to operating-system RNG
//! failure, documented at each site; see [`error`] for the reasoning.

/// AegisPQC cryptographic primitives are NOT independently audited.
/// Do not rely on this code for life-critical communications until a
/// third-party cryptographic audit has been completed. See
/// `AEGIS.Plan.V0.2.md`, document header, and Section 9.1.
pub const SECURITY_DISCLAIMER: &str =
    "AegisPQC cryptographic primitives are NOT independently audited. \
     Do not rely on this code for life-critical communications until a \
     third-party cryptographic audit has been completed.";

pub mod aead;
pub mod ecdh;
pub mod error;
pub mod hybrid;
pub mod kdf;
pub mod kem;
pub mod passphrase;
pub mod sas;
pub mod signature;
pub mod version;

pub use error::CryptoError;

#[cfg(test)]
mod tests {
    use super::SECURITY_DISCLAIMER;

    #[test]
    fn disclaimer_states_not_audited() {
        assert!(SECURITY_DISCLAIMER.contains("NOT independently audited"));
    }
}
