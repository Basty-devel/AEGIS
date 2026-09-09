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
    /// Self-signature over `ecdh`'s public key, under `signing` —
    /// see [`verify_identity_ecdh_binding`]. Computed once in
    /// [`IdentityKeyPair::generate`] rather than on each
    /// [`IdentityKeyPair::public_keys`] call: ML-DSA-87 signing is
    /// expensive and randomized, so re-signing per call would both
    /// cost more and produce a different (still valid) signature
    /// every time, making `public_keys()` non-deterministic.
    pub ecdh_public_signature: EncodedDualSignature,
}

/// The public half of [`IdentityKeyPair`], as published in a
/// [`PreKeyBundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeys {
    pub verifying: DualVerifyingKey,
    pub ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    /// Proof that `ecdh_public` belongs to the same identity as
    /// `verifying` — see [`verify_identity_ecdh_binding`].
    pub ecdh_public_signature: EncodedDualSignature,
}

/// Domain-separation label for the identity self-signature, keeping
/// its signing input disjoint from [`signed_pre_key_signing_input`]'s
/// (spec §9.1's domain-separation discipline: two different things
/// signed by the same key must never share a message space).
const IDENTITY_ECDH_BINDING_LABEL: &[u8] = b"AEGIS-IDENTITY-ECDH-BINDING-v1";

fn identity_ecdh_binding_signing_input(ecdh_public: &[u8; ECDH_PUBLIC_KEY_LEN]) -> Vec<u8> {
    let mut input = Vec::with_capacity(IDENTITY_ECDH_BINDING_LABEL.len() + ECDH_PUBLIC_KEY_LEN);
    input.extend_from_slice(IDENTITY_ECDH_BINDING_LABEL);
    input.extend_from_slice(ecdh_public);
    input
}

/// Verify that `identity.ecdh_public` really belongs to the identity
/// named by `identity.verifying`.
///
/// Without this check there is **no** cryptographic link between the
/// two halves of an [`IdentityKeys`]: X3DH's implicit authentication
/// lives entirely in the DH1/DH2 legs, which use `ecdh_public`, while
/// the only thing a peer can actually name an identity by is
/// `verifying`. An attacker could therefore present a victim's real
/// dual verifying key alongside their *own* identity ECDH key — every
/// DH/KEM leg would agree, both sides would derive the same root key,
/// and the responder's only identity assertion would be one the
/// attacker supplied (final-review finding C3, responder-side
/// impersonation). Signing `ecdh_public` under the same identity's
/// `DualKeyPair` at generation time closes that gap without needing a
/// PKI or key-directory concept, which is out of scope for Phase 1.
///
/// Both [`crate::x3dh::initiate_x3dh`] and
/// [`crate::x3dh::respond_to_x3dh`] call this before using
/// `ecdh_public` for any DH computation.
pub fn verify_identity_ecdh_binding(identity: &IdentityKeys) -> bool {
    let signing_input = identity_ecdh_binding_signing_input(&identity.ecdh_public);
    let sig = DualSignature {
        ed25519: identity.ecdh_public_signature.ed25519,
        ml_dsa87: identity.ecdh_public_signature.ml_dsa87.to_vec(),
    };
    verify_dual(
        &identity.verifying.ed25519,
        &identity.verifying.ml_dsa87,
        &signing_input,
        &sig,
    )
}

impl IdentityKeyPair {
    /// Generate a fresh long-term identity, including the
    /// self-signature that binds its ECDH public key to its signing
    /// identity ([`verify_identity_ecdh_binding`]).
    pub fn generate() -> Self {
        let signing = DualKeyPair::generate();
        let ecdh = Brainpool512SecretKey::generate();
        let ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN] = ecdh
            .public_key_bytes()
            .try_into()
            .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes for brainpool512r1");
        let ecdh_public_signature =
            (&signing.sign(&identity_ecdh_binding_signing_input(&ecdh_public)))
                .try_into()
                .expect("DualKeyPair::sign always produces ML_DSA_87_SIGNATURE_LEN bytes");
        Self {
            signing,
            ecdh,
            ecdh_public_signature,
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
            ecdh_public_signature: self.ecdh_public_signature.clone(),
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

/// Domain-separation label for a signed pre-key's signature. Its
/// message space is disjoint from [`IDENTITY_ECDH_BINDING_LABEL`]'s
/// both by label and by length, so one identity's `DualKeyPair` can
/// never be tricked into producing a signature valid in the other
/// context.
const SIGNED_PRE_KEY_LABEL: &[u8] = b"AEGIS-SIGNED-PRE-KEY-v1";

fn signed_pre_key_signing_input(
    ecdh_public: &[u8; ECDH_PUBLIC_KEY_LEN],
    kem_encapsulation_key: &[u8; KEM_ENCAPSULATION_KEY_LEN],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        SIGNED_PRE_KEY_LABEL.len() + ECDH_PUBLIC_KEY_LEN + KEM_ENCAPSULATION_KEY_LEN,
    );
    input.extend_from_slice(SIGNED_PRE_KEY_LABEL);
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
        out.extend_from_slice(&self.identity.ecdh_public_signature.ed25519);
        out.extend_from_slice(&self.identity.ecdh_public_signature.ml_dsa87);
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
            ecdh_public_signature: EncodedDualSignature {
                ed25519: cursor.take_array::<ED25519_SIGNATURE_LEN>()?,
                ml_dsa87: cursor.take_array::<ML_DSA_87_SIGNATURE_LEN>()?,
            },
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
    fn identity_ecdh_binding_verifies_for_a_freshly_generated_identity() {
        let identity = IdentityKeyPair::generate();
        assert!(verify_identity_ecdh_binding(&identity.public_keys()));
    }

    #[test]
    fn identity_ecdh_binding_rejects_a_swapped_ecdh_key() {
        // Final-review finding C3: the core impersonation primitive is
        // "take a real party's verifying keys, attach a different
        // (attacker-held) identity ECDH key". That combination must not
        // verify.
        let victim = IdentityKeyPair::generate();
        let attacker = IdentityKeyPair::generate();

        let mut forged = victim.public_keys();
        forged.ecdh_public = attacker.public_keys().ecdh_public;
        assert!(!verify_identity_ecdh_binding(&forged));

        // Nor does pairing the attacker's ECDH key with the attacker's
        // own signature under the victim's verifying key.
        forged.ecdh_public_signature = attacker.public_keys().ecdh_public_signature;
        assert!(!verify_identity_ecdh_binding(&forged));
    }

    #[test]
    fn identity_ecdh_binding_rejects_a_tampered_signature() {
        let identity = IdentityKeyPair::generate();
        let mut keys = identity.public_keys();
        keys.ecdh_public_signature.ed25519[0] ^= 0xFF;
        assert!(!verify_identity_ecdh_binding(&keys));

        let mut keys = identity.public_keys();
        keys.ecdh_public_signature.ml_dsa87[0] ^= 0xFF;
        assert!(!verify_identity_ecdh_binding(&keys));
    }

    #[test]
    fn public_keys_returns_the_same_binding_signature_every_call() {
        // ML-DSA-87 signing is randomized: re-signing on each
        // `public_keys()` call would hand out a different (still valid)
        // signature every time, so the signature is computed once at
        // generation and cloned out here.
        let identity = IdentityKeyPair::generate();
        assert_eq!(
            identity.public_keys().ecdh_public_signature,
            identity.public_keys().ecdh_public_signature,
        );
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
        assert!(
            verify_identity_ecdh_binding(&decoded.identity),
            "the identity ECDH binding signature must survive the wire round trip",
        );
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
