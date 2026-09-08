//! Long-term identity keys and pre-key bundles for PQ-X3DH (design
//! §2). `aegis_crypto::signature::DualKeyPair` is signing-only
//! (Ed25519 + ML-DSA-87); X3DH additionally needs a long-term
//! brainpool512r1 keypair for its DH legs, so [`IdentityKeyPair`]
//! bundles both — see this plan's Global Constraints.

use crate::error::RatchetError;
use aegis_crypto::ecdh::Brainpool512SecretKey;
use aegis_crypto::kem::MlKem1024KeyPair;
use aegis_crypto::signature::{verify_dual, DualKeyPair, DualSignature};

/// Uncompressed SEC1 brainpool512r1 public key length: `0x04 || X ||
/// Y`, each coordinate 64 bytes (RFC 5639 §3.7 field size).
pub const ECDH_PUBLIC_KEY_LEN: usize = 129;
/// FIPS 203 Table 3.
pub const KEM_ENCAPSULATION_KEY_LEN: usize = 1568;
/// FIPS 203 Table 3.
pub const KEM_CIPHERTEXT_LEN: usize = 1568;
/// RFC 8032.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// FIPS 204 Table 2 (ML-DSA-87 public key).
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
/// RFC 8032.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// FIPS 204 Table 2 (ML-DSA-87 signature).
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;

/// A dual (Ed25519 + ML-DSA-87) verifying key, fixed-size for wire
/// encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualVerifyingKey {
    pub ed25519: [u8; ED25519_PUBLIC_KEY_LEN],
    pub ml_dsa87: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
}

/// A dual signature, fixed-size for wire encoding (contrast with
/// `aegis_crypto::signature::DualSignature`, whose `ml_dsa87` field is
/// a `Vec<u8>` — this type is the frozen-length wire form of it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedDualSignature {
    pub ed25519: [u8; ED25519_SIGNATURE_LEN],
    pub ml_dsa87: [u8; ML_DSA_87_SIGNATURE_LEN],
}

impl TryFrom<&DualSignature> for EncodedDualSignature {
    type Error = RatchetError;

    fn try_from(sig: &DualSignature) -> Result<Self, RatchetError> {
        Ok(Self {
            ed25519: sig.ed25519,
            ml_dsa87: sig
                .ml_dsa87
                .as_slice()
                .try_into()
                .map_err(|_| RatchetError::MalformedMessage)?,
        })
    }
}

/// A party's full long-term identity: a signing keypair plus a
/// separate brainpool512r1 DH keypair (X3DH needs both; see this
/// plan's Global Constraints).
pub struct IdentityKeyPair {
    pub signing: DualKeyPair,
    pub ecdh: Brainpool512SecretKey,
}

/// The public half of [`IdentityKeyPair`], as published in a
/// [`PreKeyBundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeys {
    pub verifying: DualVerifyingKey,
    pub ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
}

impl IdentityKeyPair {
    /// Generate a fresh long-term identity.
    pub fn generate() -> Self {
        Self {
            signing: DualKeyPair::generate(),
            ecdh: Brainpool512SecretKey::generate(),
        }
    }

    pub fn public_keys(&self) -> IdentityKeys {
        IdentityKeys {
            verifying: DualVerifyingKey {
                ed25519: self.signing.ed25519_public_bytes(),
                ml_dsa87: self
                    .signing
                    .ml_dsa87_public_bytes()
                    .try_into()
                    .expect("ml_dsa87_public_bytes is always ML_DSA_87_PUBLIC_KEY_LEN bytes"),
            },
            ecdh_public: self
                .ecdh
                .public_key_bytes()
                .try_into()
                .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes for brainpool512r1"),
        }
    }
}

/// A signed pre-key: fresh ECDH + KEM material, signed by the identity
/// key, published as part of a [`PreKeyBundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPreKey {
    pub ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    pub kem_encapsulation_key: [u8; KEM_ENCAPSULATION_KEY_LEN],
    pub signature: EncodedDualSignature,
}

fn signed_pre_key_signing_input(
    ecdh_public: &[u8; ECDH_PUBLIC_KEY_LEN],
    kem_encapsulation_key: &[u8; KEM_ENCAPSULATION_KEY_LEN],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(ECDH_PUBLIC_KEY_LEN + KEM_ENCAPSULATION_KEY_LEN);
    input.extend_from_slice(ecdh_public);
    input.extend_from_slice(kem_encapsulation_key);
    input
}

/// Generate a signed pre-key under `identity`. Returns the public
/// [`SignedPreKey`] to publish plus the two private keypairs the
/// generating party must retain to answer an incoming X3DH handshake
/// (Task 5).
pub fn generate_signed_pre_key(
    identity: &IdentityKeyPair,
) -> (SignedPreKey, Brainpool512SecretKey, MlKem1024KeyPair) {
    let ecdh = Brainpool512SecretKey::generate();
    let kem = MlKem1024KeyPair::generate();
    let ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN] = ecdh
        .public_key_bytes()
        .try_into()
        .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes");
    let kem_encapsulation_key: [u8; KEM_ENCAPSULATION_KEY_LEN] = kem
        .encapsulation_key_bytes()
        .try_into()
        .expect("encapsulation_key_bytes is always KEM_ENCAPSULATION_KEY_LEN bytes");

    let signing_input = signed_pre_key_signing_input(&ecdh_public, &kem_encapsulation_key);
    let signature = (&identity.signing.sign(&signing_input))
        .try_into()
        .expect("DualKeyPair::sign always produces ML_DSA_87_SIGNATURE_LEN bytes");

    (
        SignedPreKey {
            ecdh_public,
            kem_encapsulation_key,
            signature,
        },
        ecdh,
        kem,
    )
}

/// Verify a [`SignedPreKey`]'s signature against `identity`.
pub fn verify_signed_pre_key(identity: &IdentityKeys, spk: &SignedPreKey) -> bool {
    let signing_input = signed_pre_key_signing_input(&spk.ecdh_public, &spk.kem_encapsulation_key);
    let sig = DualSignature {
        ed25519: spk.signature.ed25519,
        ml_dsa87: spk.signature.ml_dsa87.to_vec(),
    };
    verify_dual(
        &identity.verifying.ed25519,
        &identity.verifying.ml_dsa87,
        &signing_input,
        &sig,
    )
}

/// A single-use pre-key: fresh, unsigned ECDH + KEM material, consumed
/// on use (design §2.1 — matches Signal's OPK).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimePreKey {
    pub id: u32,
    pub ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    pub kem_encapsulation_key: [u8; KEM_ENCAPSULATION_KEY_LEN],
}

/// Generate a one-time pre-key with the given bookkeeping `id`.
/// Returns the public [`OneTimePreKey`] plus the private keypairs the
/// generating party must retain (and discard after one use).
pub fn generate_one_time_pre_key(id: u32) -> (OneTimePreKey, Brainpool512SecretKey, MlKem1024KeyPair) {
    let ecdh = Brainpool512SecretKey::generate();
    let kem = MlKem1024KeyPair::generate();
    let ecdh_public = ecdh
        .public_key_bytes()
        .try_into()
        .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes");
    let kem_encapsulation_key = kem
        .encapsulation_key_bytes()
        .try_into()
        .expect("encapsulation_key_bytes is always KEM_ENCAPSULATION_KEY_LEN bytes");
    (
        OneTimePreKey {
            id,
            ecdh_public,
            kem_encapsulation_key,
        },
        ecdh,
        kem,
    )
}

/// What one party publishes so others can start an X3DH handshake
/// with them (design §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreKeyBundle {
    pub identity: IdentityKeys,
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_key: Option<OneTimePreKey>,
}

impl PreKeyBundle {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.identity.verifying.ed25519);
        out.extend_from_slice(&self.identity.verifying.ml_dsa87);
        out.extend_from_slice(&self.identity.ecdh_public);
        out.extend_from_slice(&self.signed_pre_key.ecdh_public);
        out.extend_from_slice(&self.signed_pre_key.kem_encapsulation_key);
        out.extend_from_slice(&self.signed_pre_key.signature.ed25519);
        out.extend_from_slice(&self.signed_pre_key.signature.ml_dsa87);
        match &self.one_time_pre_key {
            None => out.push(0x00),
            Some(otpk) => {
                out.push(0x01);
                out.extend_from_slice(&otpk.id.to_be_bytes());
                out.extend_from_slice(&otpk.ecdh_public);
                out.extend_from_slice(&otpk.kem_encapsulation_key);
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut cursor = ByteCursor::new(bytes);
        let identity = IdentityKeys {
            verifying: DualVerifyingKey {
                ed25519: cursor.take_array::<ED25519_PUBLIC_KEY_LEN>()?,
                ml_dsa87: cursor.take_array::<ML_DSA_87_PUBLIC_KEY_LEN>()?,
            },
            ecdh_public: cursor.take_array::<ECDH_PUBLIC_KEY_LEN>()?,
        };
        let signed_pre_key = SignedPreKey {
            ecdh_public: cursor.take_array::<ECDH_PUBLIC_KEY_LEN>()?,
            kem_encapsulation_key: cursor.take_array::<KEM_ENCAPSULATION_KEY_LEN>()?,
            signature: EncodedDualSignature {
                ed25519: cursor.take_array::<ED25519_SIGNATURE_LEN>()?,
                ml_dsa87: cursor.take_array::<ML_DSA_87_SIGNATURE_LEN>()?,
            },
        };
        let has_otpk = cursor.take_byte()?;
        let one_time_pre_key = match has_otpk {
            0x00 => None,
            0x01 => Some(OneTimePreKey {
                id: u32::from_be_bytes(cursor.take_array::<4>()?),
                ecdh_public: cursor.take_array::<ECDH_PUBLIC_KEY_LEN>()?,
                kem_encapsulation_key: cursor.take_array::<KEM_ENCAPSULATION_KEY_LEN>()?,
            }),
            _ => return Err(RatchetError::MalformedPreKeyBundle),
        };
        Ok(Self {
            identity,
            signed_pre_key,
            one_time_pre_key,
        })
    }
}

/// A minimal forward-only byte reader used by every wire-format
/// `from_bytes` in this crate: takes fixed-size chunks off the front,
/// erroring (never panicking) on truncation.
pub(crate) struct ByteCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> ByteCursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    pub(crate) fn take_array<const N: usize>(&mut self) -> Result<[u8; N], RatchetError> {
        if self.remaining.len() < N {
            return Err(RatchetError::MalformedPreKeyBundle);
        }
        let (chunk, rest) = self.remaining.split_at(N);
        self.remaining = rest;
        Ok(chunk.try_into().expect("split_at(N) guarantees N bytes"))
    }

    pub(crate) fn take_byte(&mut self) -> Result<u8, RatchetError> {
        let arr = self.take_array::<1>()?;
        Ok(arr[0])
    }

    // `take_vec` and `remaining` have no caller within this task: this
    // module (`prekey`) only needs `take_array`/`take_byte`. They exist
    // here because `ByteCursor` is defined once and reused — Task 4's
    // `AegisX3DHInitialMessage` and Task 6's `RatchetHeader`/
    // `RatchetMessage` import `crate::prekey::ByteCursor` and call
    // these for their own variable-length/tail-reading needs rather
    // than redefining the type. `#[allow(dead_code)]` is scoped to
    // exactly these two methods so an accidental future dead method
    // elsewhere in this file would still be caught.
    #[allow(dead_code)]
    pub(crate) fn take_vec(&mut self, len: usize) -> Result<Vec<u8>, RatchetError> {
        if self.remaining.len() < len {
            return Err(RatchetError::MalformedPreKeyBundle);
        }
        let (chunk, rest) = self.remaining.split_at(len);
        self.remaining = rest;
        Ok(chunk.to_vec())
    }

    #[allow(dead_code)]
    pub(crate) fn remaining(&self) -> &[u8] {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_pre_key_verifies_against_its_own_identity() {
        let identity = IdentityKeyPair::generate();
        let (spk, _ecdh_priv, _kem_priv) = generate_signed_pre_key(&identity);
        assert!(verify_signed_pre_key(&identity.public_keys(), &spk));
    }

    #[test]
    fn signed_pre_key_fails_against_a_different_identity() {
        let identity = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();
        let (spk, _, _) = generate_signed_pre_key(&identity);
        assert!(!verify_signed_pre_key(&other.public_keys(), &spk));
    }

    #[test]
    fn tampered_signed_pre_key_ecdh_public_fails_verification() {
        let identity = IdentityKeyPair::generate();
        let (mut spk, _, _) = generate_signed_pre_key(&identity);
        spk.ecdh_public[0] ^= 0xFF;
        assert!(!verify_signed_pre_key(&identity.public_keys(), &spk));
    }

    #[test]
    fn bundle_round_trips_through_wire_bytes() {
        let identity = IdentityKeyPair::generate();
        let (signed_pre_key, _, _) = generate_signed_pre_key(&identity);
        let (one_time_pre_key, _, _) = generate_one_time_pre_key(7);
        let bundle = PreKeyBundle {
            identity: identity.public_keys(),
            signed_pre_key,
            one_time_pre_key: Some(one_time_pre_key),
        };

        let bytes = bundle.to_bytes();
        let decoded = PreKeyBundle::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.identity.ecdh_public, bundle.identity.ecdh_public);
        assert_eq!(decoded.signed_pre_key.ecdh_public, bundle.signed_pre_key.ecdh_public);
        assert_eq!(
            decoded.one_time_pre_key.as_ref().unwrap().id,
            bundle.one_time_pre_key.as_ref().unwrap().id,
        );
        assert!(verify_signed_pre_key(&decoded.identity, &decoded.signed_pre_key));
    }

    #[test]
    fn bundle_without_one_time_pre_key_round_trips() {
        let identity = IdentityKeyPair::generate();
        let (signed_pre_key, _, _) = generate_signed_pre_key(&identity);
        let bundle = PreKeyBundle {
            identity: identity.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };

        let decoded = PreKeyBundle::from_bytes(&bundle.to_bytes()).unwrap();
        assert!(decoded.one_time_pre_key.is_none());
    }

    #[test]
    fn truncated_bundle_bytes_are_rejected_without_panicking() {
        let identity = IdentityKeyPair::generate();
        let (signed_pre_key, _, _) = generate_signed_pre_key(&identity);
        let bundle = PreKeyBundle {
            identity: identity.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };
        let bytes = bundle.to_bytes();
        for cut in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert_eq!(
                PreKeyBundle::from_bytes(&bytes[..cut]).unwrap_err(),
                RatchetError::MalformedPreKeyBundle,
            );
        }
    }
}
