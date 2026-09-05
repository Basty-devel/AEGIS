//! Hybrid ML-KEM-1024 + brainpool512r1 KEM combiner. See
//! AEGIS.Plan.V0.2.md Section 2.
//!
//! Construction: `K = HKDF-SHA512(SS_brainpool512r1 || SS_ML-KEM-1024,
//! info = domain_label || protocol_version || pubkey_A || pubkey_B)`.
//! Reference: NIST SP 800-56C (concatenation KDF combiner).
//!
//! The classical secret comes first in the IKM and both secrets are
//! always included, so the combined key is at least as strong as the
//! stronger of the two components.

use crate::ecdh::{brainpool512_diffie_hellman, Brainpool512SecretKey};
use crate::error::CryptoError;
use crate::kdf::derive_key;
use crate::kem::{ml_kem_decapsulate, ml_kem_encapsulate, MlKem1024KeyPair};
use crate::version::ProtocolVersion;
use zeroize::Zeroizing;

const DOMAIN_LABEL: &[u8] = b"AegisPQC-v1-HybridKEM";

/// Length of the key produced by the combiner.
pub const HYBRID_KEY_LEN: usize = 32;

/// The shared key produced by the combiner. Wrapped in [`Zeroizing`] so
/// callers cannot accidentally leave it in memory after use.
pub type HybridSharedKey = Zeroizing<[u8; HYBRID_KEY_LEN]>;

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
///
/// `protocol_version` is a [`ProtocolVersion`], not a raw `u8`, so it
/// is structurally impossible for an unrecognised version byte to reach
/// the KDF: unknown bytes are rejected by
/// [`crate::version::parse_protocol_version`] at the point they are
/// parsed off the wire, before this function is ever called.
///
/// # Errors
///
/// Propagates [`CryptoError`] from the two component KEMs — in
/// practice, a malformed `peer_keys.brainpool512` or
/// `peer_keys.ml_kem1024_ek`.
///
/// # Panics
///
/// Panics only if the operating system RNG fails; see
/// [`Brainpool512SecretKey::generate`] and
/// [`crate::kem::ml_kem_encapsulate`] for why that is fail-closed
/// rather than an error return.
pub fn hybrid_kem_encapsulate(
    protocol_version: ProtocolVersion,
    peer_keys: &HybridPublicKeys,
) -> Result<(HybridCiphertext, HybridSharedKey), CryptoError> {
    encapsulate_with_version_byte(protocol_version as u8, peer_keys)
}

/// Decapsulate a bundle produced by [`hybrid_kem_encapsulate`] using
/// our own long-term keys.
///
/// # Errors
///
/// Propagates [`CryptoError`] from the two component KEMs. Every field
/// of `ciphertext` arrives from the network, so a malformed bundle
/// yields an error rather than a panic.
pub fn hybrid_kem_decapsulate(
    protocol_version: ProtocolVersion,
    our_brainpool_secret: &Brainpool512SecretKey,
    our_ml_kem: &MlKem1024KeyPair,
    our_public_keys: &HybridPublicKeys,
    ciphertext: &HybridCiphertext,
) -> Result<HybridSharedKey, CryptoError> {
    decapsulate_with_version_byte(
        protocol_version as u8,
        our_brainpool_secret,
        our_ml_kem,
        our_public_keys,
        ciphertext,
    )
}

/// Combiner body, parameterised on the raw version byte.
///
/// Only [`hybrid_kem_encapsulate`] (which can only be handed a valid
/// [`ProtocolVersion`]) and the version-binding regression test call
/// this. Keeping the raw-byte form private is what makes "no unknown
/// version reaches the KDF" structural rather than a convention.
fn encapsulate_with_version_byte(
    version_byte: u8,
    peer_keys: &HybridPublicKeys,
) -> Result<(HybridCiphertext, HybridSharedKey), CryptoError> {
    let ephemeral_brainpool = Brainpool512SecretKey::generate();
    let ephemeral_public = ephemeral_brainpool.public_key_bytes();
    let brainpool_shared =
        brainpool512_diffie_hellman(&ephemeral_brainpool, &peer_keys.brainpool512)?;
    let (ml_kem_ciphertext, ml_kem_shared) = ml_kem_encapsulate(&peer_keys.ml_kem1024_ek)?;

    let key = combine(
        brainpool_shared.as_slice(),
        ml_kem_shared.as_slice(),
        version_byte,
        &ephemeral_public,
        &peer_keys.brainpool512,
    )?;

    Ok((
        HybridCiphertext {
            brainpool512_ephemeral_public: ephemeral_public,
            ml_kem1024_ciphertext: ml_kem_ciphertext,
        },
        key,
    ))
}

/// Decapsulation counterpart of [`encapsulate_with_version_byte`].
fn decapsulate_with_version_byte(
    version_byte: u8,
    our_brainpool_secret: &Brainpool512SecretKey,
    our_ml_kem: &MlKem1024KeyPair,
    our_public_keys: &HybridPublicKeys,
    ciphertext: &HybridCiphertext,
) -> Result<HybridSharedKey, CryptoError> {
    let brainpool_shared = brainpool512_diffie_hellman(
        our_brainpool_secret,
        &ciphertext.brainpool512_ephemeral_public,
    )?;
    let ml_kem_shared = ml_kem_decapsulate(our_ml_kem, &ciphertext.ml_kem1024_ciphertext)?;

    combine(
        brainpool_shared.as_slice(),
        ml_kem_shared.as_slice(),
        version_byte,
        &ciphertext.brainpool512_ephemeral_public,
        &our_public_keys.brainpool512,
    )
}

/// The actual SP 800-56C concatenation step, shared by both directions
/// so the two can never drift apart.
///
/// `ikm` holds both raw shared secrets concatenated and is wiped on
/// drop; without that the combined input to the KDF — which is enough
/// to rederive the session key — would outlive this function on the
/// heap.
fn combine(
    brainpool_shared: &[u8],
    ml_kem_shared: &[u8],
    version_byte: u8,
    pubkey_a: &[u8],
    pubkey_b: &[u8],
) -> Result<HybridSharedKey, CryptoError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        brainpool_shared.len() + ml_kem_shared.len(),
    ));
    ikm.extend_from_slice(brainpool_shared);
    ikm.extend_from_slice(ml_kem_shared);

    let mut key: HybridSharedKey = Zeroizing::new([0u8; HYBRID_KEY_LEN]);
    derive_key(
        &ikm,
        DOMAIN_LABEL,
        version_byte,
        pubkey_a,
        pubkey_b,
        key.as_mut(),
    )?;
    Ok(key)
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

        let (ciphertext, sender_key) =
            hybrid_kem_encapsulate(ProtocolVersion::V1, &alice_public).unwrap();
        let receiver_key = hybrid_kem_decapsulate(
            ProtocolVersion::V1,
            &alice_brainpool,
            &alice_ml_kem,
            &alice_public,
            &ciphertext,
        )
        .unwrap();

        assert_eq!(*sender_key, *receiver_key);
    }

    #[test]
    fn different_protocol_versions_derive_different_keys() {
        let brainpool = Brainpool512SecretKey::generate();
        let ml_kem = MlKem1024KeyPair::generate();
        let public = keys_for(&brainpool, &ml_kem);

        let (ciphertext_v1, key_v1) =
            hybrid_kem_encapsulate(ProtocolVersion::V1, &public).unwrap();
        let key_v1_decap = hybrid_kem_decapsulate(
            ProtocolVersion::V1,
            &brainpool,
            &ml_kem,
            &public,
            &ciphertext_v1,
        )
        .unwrap();
        assert_eq!(*key_v1, *key_v1_decap);

        // Re-deriving with a mismatched version byte on the decapsulating
        // side must NOT produce the same key as the sender used — proves
        // the version byte is actually bound into the KDF info, not
        // decorative. Reaches for the private raw-byte form because the
        // public API (correctly) makes an unknown version byte
        // unrepresentable.
        let key_wrong_version =
            decapsulate_with_version_byte(2, &brainpool, &ml_kem, &public, &ciphertext_v1).unwrap();
        assert_ne!(*key_v1, *key_wrong_version);
    }

    #[test]
    fn typed_protocol_version_reaches_the_kdf_as_its_discriminant() {
        let brainpool = Brainpool512SecretKey::generate();
        let ml_kem = MlKem1024KeyPair::generate();
        let public = keys_for(&brainpool, &ml_kem);

        let (ciphertext, _) = hybrid_kem_encapsulate(ProtocolVersion::V1, &public).unwrap();

        let via_typed = hybrid_kem_decapsulate(
            ProtocolVersion::V1,
            &brainpool,
            &ml_kem,
            &public,
            &ciphertext,
        )
        .unwrap();
        let via_raw_byte =
            decapsulate_with_version_byte(1, &brainpool, &ml_kem, &public, &ciphertext).unwrap();

        assert_eq!(
            *via_typed, *via_raw_byte,
            "ProtocolVersion::V1 must be bound into the KDF as the byte 1",
        );
    }

    #[test]
    fn malformed_ciphertext_bundle_is_rejected_without_panicking() {
        let brainpool = Brainpool512SecretKey::generate();
        let ml_kem = MlKem1024KeyPair::generate();
        let public = keys_for(&brainpool, &ml_kem);
        let (good, _) = hybrid_kem_encapsulate(ProtocolVersion::V1, &public).unwrap();

        let bad_ephemeral = HybridCiphertext {
            brainpool512_ephemeral_public: b"not a point".to_vec(),
            ml_kem1024_ciphertext: good.ml_kem1024_ciphertext.clone(),
        };
        assert_eq!(
            hybrid_kem_decapsulate(
                ProtocolVersion::V1,
                &brainpool,
                &ml_kem,
                &public,
                &bad_ephemeral,
            )
            .unwrap_err(),
            CryptoError::InvalidPeerPublicKey,
        );

        let bad_kem_ct = HybridCiphertext {
            brainpool512_ephemeral_public: good.brainpool512_ephemeral_public.clone(),
            ml_kem1024_ciphertext: vec![0u8; 7],
        };
        assert_eq!(
            hybrid_kem_decapsulate(
                ProtocolVersion::V1,
                &brainpool,
                &ml_kem,
                &public,
                &bad_kem_ct,
            )
            .unwrap_err(),
            CryptoError::InvalidCiphertextLength {
                expected: crate::kem::ML_KEM_1024_CIPHERTEXT_LEN,
                actual: 7,
            },
        );
    }

    #[test]
    fn malformed_peer_keys_are_rejected_on_encapsulate_without_panicking() {
        let brainpool = Brainpool512SecretKey::generate();
        let ml_kem = MlKem1024KeyPair::generate();

        let bad_brainpool = HybridPublicKeys {
            brainpool512: b"not a point".to_vec(),
            ml_kem1024_ek: ml_kem.encapsulation_key_bytes(),
        };
        assert_eq!(
            hybrid_kem_encapsulate(ProtocolVersion::V1, &bad_brainpool)
                .err()
                .unwrap(),
            CryptoError::InvalidPeerPublicKey,
        );

        let bad_ek = HybridPublicKeys {
            brainpool512: brainpool.public_key_bytes(),
            ml_kem1024_ek: vec![0u8; 3],
        };
        assert_eq!(
            hybrid_kem_encapsulate(ProtocolVersion::V1, &bad_ek).err().unwrap(),
            CryptoError::InvalidEncapsulationKeyLength {
                expected: crate::kem::ML_KEM_1024_ENCAPSULATION_KEY_LEN,
                actual: 3,
            },
        );
    }
}
