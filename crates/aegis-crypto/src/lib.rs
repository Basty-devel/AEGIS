//! Hybrid cryptographic primitives: ML-KEM-1024 + brainpool512r1 KEM
//! combiner, ML-DSA-87 + Ed25519 signatures, AEAD, Argon2id, HKDF-SHA512,
//! and memory zeroization.
//!
//! See `AEGIS.Plan.V0.2.md` Sections 2 and 9.1 (cryptographic ground
//! rules — no construction here may deviate from a cited published
//! reference).

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
pub mod hybrid;
pub mod kdf;
pub mod kem;
pub mod passphrase;
pub mod sas;
pub mod signature;
pub mod version;

#[cfg(test)]
mod tests {
    use super::SECURITY_DISCLAIMER;

    #[test]
    fn disclaimer_states_not_audited() {
        assert!(SECURITY_DISCLAIMER.contains("NOT independently audited"));
    }
}
