//! PQ-X3DH handshake (design §2). Extends Signal's X3DH
//! (<https://signal.org/docs/specifications/x3dh/>) from a 3-DH
//! combiner to a hybrid 4-leg combiner: the three classical DH legs
//! are unchanged, plus one ML-KEM-1024 encapsulation leg (two, if the
//! bundle includes a one-time pre-key).

use crate::error::RatchetError;
use crate::kdf_chain::ROOT_KEY_LEN;
use crate::prekey::{
    verify_identity_ecdh_binding, verify_signed_pre_key, ByteCursor, DualVerifyingKey,
    EncodedDualSignature, IdentityKeyPair, IdentityKeys, PreKeyBundle, ECDH_PUBLIC_KEY_LEN,
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, KEM_CIPHERTEXT_LEN, ML_DSA_87_PUBLIC_KEY_LEN,
    ML_DSA_87_SIGNATURE_LEN,
};
use aegis_crypto::ecdh::{brainpool512_diffie_hellman, Brainpool512SecretKey};
use aegis_crypto::kdf::derive_key;
use aegis_crypto::kem::{ml_kem_decapsulate, ml_kem_encapsulate, MlKem1024KeyPair};
use aegis_crypto::version::ProtocolVersion;
use zeroize::Zeroizing;

const X3DH_DOMAIN_LABEL: &[u8] = b"AEGIS-X3DH-v1";

/// One party's identity as it enters `derive_key`'s `info` transcript:
/// dual verifying key **and** long-term ECDH public key.
///
/// The ECDH half is not decoration. X3DH's implicit authentication is
/// carried entirely by the DH1/DH2 legs, which use `ecdh_public` — so
/// binding only the verifying keys (as this crate originally did) ties
/// the derived root key to the *claimed* identities while leaving the
/// actual DH material unbound (final-review finding C3). Including it
/// here means two handshakes that used different identity DH keys can
/// never derive the same root key, even if the claimed verifying keys
/// match.
///
/// Every component is fixed-length (32 + 2592 + 129 = 2753 bytes), so
/// the concatenation is injective on its own; `derive_key` then frames
/// the whole value with a `u16` length prefix, keeping the `pubkey_a` /
/// `pubkey_b` boundary unambiguous too.
fn identity_transcript_bytes(
    verifying: &DualVerifyingKey,
    ecdh_public: &[u8; ECDH_PUBLIC_KEY_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        ED25519_PUBLIC_KEY_LEN + ML_DSA_87_PUBLIC_KEY_LEN + ECDH_PUBLIC_KEY_LEN,
    );
    out.extend_from_slice(&verifying.ed25519);
    out.extend_from_slice(&verifying.ml_dsa87);
    out.extend_from_slice(ecdh_public);
    out
}

/// Everything a X3DH initial handshake message carries except the
/// first actual ciphertext (Task 6 combines this with a
/// `RatchetMessage` for transmission).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X3DHPreamble {
    pub protocol_version: u8,
    pub alice_identity: DualVerifyingKey,
    pub alice_identity_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    /// Alice's self-signature over `alice_identity_ecdh_public`, so
    /// Bob can check that the DH key the handshake actually used
    /// belongs to the identity the preamble claims
    /// (`crate::prekey::verify_identity_ecdh_binding`, finding C3).
    /// Without it, `respond_to_x3dh` verified nothing whatsoever about
    /// the initiator's claimed identity.
    pub alice_identity_ecdh_signature: EncodedDualSignature,
    pub alice_ephemeral_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    pub kem_ciphertext_signed: [u8; KEM_CIPHERTEXT_LEN],
    pub used_one_time_pre_key_id: Option<u32>,
    pub kem_ciphertext_onetime: Option<[u8; KEM_CIPHERTEXT_LEN]>,
}

impl X3DHPreamble {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.protocol_version);
        out.extend_from_slice(&self.alice_identity.ed25519);
        out.extend_from_slice(&self.alice_identity.ml_dsa87);
        out.extend_from_slice(&self.alice_identity_ecdh_public);
        out.extend_from_slice(&self.alice_identity_ecdh_signature.ed25519);
        out.extend_from_slice(&self.alice_identity_ecdh_signature.ml_dsa87);
        out.extend_from_slice(&self.alice_ephemeral_ecdh_public);
        out.extend_from_slice(&self.kem_ciphertext_signed);
        match self.used_one_time_pre_key_id {
            None => out.push(0x00),
            Some(id) => {
                out.push(0x01);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(
                    self.kem_ciphertext_onetime
                        .as_ref()
                        .expect("used_one_time_pre_key_id.is_some() implies kem_ciphertext_onetime.is_some()"),
                );
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut cursor = ByteCursor::new(bytes);
        let protocol_version = cursor.take_byte().map_err(|_| RatchetError::MalformedMessage)?;
        let alice_identity = DualVerifyingKey {
            ed25519: cursor
                .take_array::<ED25519_PUBLIC_KEY_LEN>()
                .map_err(|_| RatchetError::MalformedMessage)?,
            ml_dsa87: cursor
                .take_array::<ML_DSA_87_PUBLIC_KEY_LEN>()
                .map_err(|_| RatchetError::MalformedMessage)?,
        };
        let alice_identity_ecdh_public = cursor
            .take_array::<ECDH_PUBLIC_KEY_LEN>()
            .map_err(|_| RatchetError::MalformedMessage)?;
        let alice_identity_ecdh_signature = EncodedDualSignature {
            ed25519: cursor
                .take_array::<ED25519_SIGNATURE_LEN>()
                .map_err(|_| RatchetError::MalformedMessage)?,
            ml_dsa87: cursor
                .take_array::<ML_DSA_87_SIGNATURE_LEN>()
                .map_err(|_| RatchetError::MalformedMessage)?,
        };
        let alice_ephemeral_ecdh_public = cursor
            .take_array::<ECDH_PUBLIC_KEY_LEN>()
            .map_err(|_| RatchetError::MalformedMessage)?;
        let kem_ciphertext_signed = cursor
            .take_array::<KEM_CIPHERTEXT_LEN>()
            .map_err(|_| RatchetError::MalformedMessage)?;
        let has_otpk = cursor.take_byte().map_err(|_| RatchetError::MalformedMessage)?;
        let (used_one_time_pre_key_id, kem_ciphertext_onetime) = match has_otpk {
            0x00 => (None, None),
            0x01 => {
                let id = u32::from_be_bytes(
                    cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?,
                );
                let ct = cursor
                    .take_array::<KEM_CIPHERTEXT_LEN>()
                    .map_err(|_| RatchetError::MalformedMessage)?;
                (Some(id), Some(ct))
            }
            _ => return Err(RatchetError::MalformedMessage),
        };
        Ok(Self {
            protocol_version,
            alice_identity,
            alice_identity_ecdh_public,
            alice_identity_ecdh_signature,
            alice_ephemeral_ecdh_public,
            kem_ciphertext_signed,
            used_one_time_pre_key_id,
            kem_ciphertext_onetime,
        })
    }

    /// The initiator's claimed identity, reassembled from the
    /// preamble's three identity fields so it can be checked with
    /// [`verify_identity_ecdh_binding`].
    fn alice_identity_keys(&self) -> IdentityKeys {
        IdentityKeys {
            verifying: self.alice_identity.clone(),
            ecdh_public: self.alice_identity_ecdh_public,
            ecdh_public_signature: self.alice_identity_ecdh_signature.clone(),
        }
    }
}

/// `initiate_x3dh`'s success value: `(root_key, preamble,
/// alice_ephemeral_ecdh_public)` — the caller (Task 6) uses
/// `alice_ephemeral_ecdh_public` again as Alice's first ratchet public
/// key, so it's returned directly rather than making Task 6 re-parse
/// it out of `preamble`. Named purely to satisfy clippy's
/// `type_complexity` lint under `-D warnings`; carries no behavior of
/// its own.
pub type X3dhInitiateResult = Result<(Zeroizing<[u8; ROOT_KEY_LEN]>, X3DHPreamble, [u8; ECDH_PUBLIC_KEY_LEN]), RatchetError>;

/// Compute Alice's X3DH shared secret and preamble against Bob's
/// `peer_bundle`. Returns `(root_key, preamble, alice_ephemeral_ecdh_public)`
/// — see [`X3dhInitiateResult`] for why that shape is returned.
///
/// # Errors
///
/// Returns [`RatchetError::InvalidBundleSignature`] if
/// `peer_bundle.signed_pre_key`'s signature does not verify against
/// `peer_bundle.identity`, or if `peer_bundle.identity`'s own ECDH
/// public key is not bound to its verifying keys
/// ([`verify_identity_ecdh_binding`]). Propagates
/// [`RatchetError::Crypto`] from malformed key material.
pub fn initiate_x3dh(
    my_identity: &IdentityKeyPair,
    peer_bundle: &PreKeyBundle,
    protocol_version: ProtocolVersion,
) -> X3dhInitiateResult {
    // Check the identity binding BEFORE the signed pre-key's own
    // signature is trusted for anything: `peer_bundle.identity.verifying`
    // is what `verify_signed_pre_key` checks against, and
    // `peer_bundle.identity.ecdh_public` is what DH1/DH2 use — this is
    // the only thing tying those two halves to the same party
    // (finding C3).
    if !verify_identity_ecdh_binding(&peer_bundle.identity) {
        return Err(RatchetError::InvalidBundleSignature);
    }
    if !verify_signed_pre_key(&peer_bundle.identity, &peer_bundle.signed_pre_key) {
        return Err(RatchetError::InvalidBundleSignature);
    }

    let ephemeral = Brainpool512SecretKey::generate();
    let alice_ephemeral_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN] = ephemeral
        .public_key_bytes()
        .try_into()
        .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes");

    let dh1 = brainpool512_diffie_hellman(&my_identity.ecdh, &peer_bundle.signed_pre_key.ecdh_public)?;
    let dh2 = brainpool512_diffie_hellman(&ephemeral, &peer_bundle.identity.ecdh_public)?;
    let dh3 = brainpool512_diffie_hellman(&ephemeral, &peer_bundle.signed_pre_key.ecdh_public)?;
    let (kem_ciphertext_signed_vec, kem_ss_signed) =
        ml_kem_encapsulate(&peer_bundle.signed_pre_key.kem_encapsulation_key)?;
    let kem_ciphertext_signed: [u8; KEM_CIPHERTEXT_LEN] = kem_ciphertext_signed_vec
        .try_into()
        .expect("ml_kem_encapsulate ciphertext is always KEM_CIPHERTEXT_LEN bytes");

    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(3 * 64 + 32 + 32));
    ikm.extend_from_slice(&*dh1);
    ikm.extend_from_slice(&*dh2);
    ikm.extend_from_slice(&*dh3);
    ikm.extend_from_slice(&*kem_ss_signed);

    let (used_one_time_pre_key_id, kem_ciphertext_onetime) =
        if let Some(otpk) = &peer_bundle.one_time_pre_key {
            let (ct_vec, ss) = ml_kem_encapsulate(&otpk.kem_encapsulation_key)?;
            let ct: [u8; KEM_CIPHERTEXT_LEN] = ct_vec
                .try_into()
                .expect("ml_kem_encapsulate ciphertext is always KEM_CIPHERTEXT_LEN bytes");
            ikm.extend_from_slice(&*ss);
            (Some(otpk.id), Some(ct))
        } else {
            (None, None)
        };

    let alice_identity_pub = my_identity.public_keys();
    let alice_identity_bytes = identity_transcript_bytes(
        &alice_identity_pub.verifying,
        &alice_identity_pub.ecdh_public,
    );
    let bob_identity_bytes = identity_transcript_bytes(
        &peer_bundle.identity.verifying,
        &peer_bundle.identity.ecdh_public,
    );

    let mut root_key = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    derive_key(
        &ikm,
        X3DH_DOMAIN_LABEL,
        protocol_version as u8,
        &alice_identity_bytes,
        &bob_identity_bytes,
        root_key.as_mut(),
    )?;

    let preamble = X3DHPreamble {
        protocol_version: protocol_version as u8,
        alice_identity: alice_identity_pub.verifying,
        alice_identity_ecdh_public: alice_identity_pub.ecdh_public,
        alice_identity_ecdh_signature: alice_identity_pub.ecdh_public_signature,
        alice_ephemeral_ecdh_public,
        kem_ciphertext_signed,
        used_one_time_pre_key_id,
        kem_ciphertext_onetime,
    };

    Ok((root_key, preamble, alice_ephemeral_ecdh_public))
}

/// Compute Bob's X3DH shared secret from Alice's `preamble`, using the
/// private keypairs matching whichever pre-keys the preamble says were
/// used. Must derive the identical root key `initiate_x3dh` derived
/// for the same handshake (verified by this task's agreement tests).
///
/// # Errors
///
/// Returns [`RatchetError::InvalidBundleSignature`] if the preamble's
/// claimed identity ECDH key is not bound to its claimed verifying
/// keys ([`verify_identity_ecdh_binding`]). Propagates
/// [`RatchetError::Crypto`] from malformed key material.
///
/// Does not re-verify Bob's own signed pre-key (he is answering his
/// own published bundle, not re-checking it) — that verification
/// happens on the initiating side, against the bundle it received
/// (Task 4).
pub fn respond_to_x3dh(
    my_identity: &IdentityKeyPair,
    my_signed_pre_key_ecdh: &Brainpool512SecretKey,
    my_signed_pre_key_kem: &MlKem1024KeyPair,
    my_one_time_pre_key: Option<(&Brainpool512SecretKey, &MlKem1024KeyPair)>,
    preamble: &X3DHPreamble,
) -> Result<Zeroizing<[u8; ROOT_KEY_LEN]>, RatchetError> {
    // The responder previously verified *nothing* about the initiator's
    // claimed identity (finding C3). Everything Bob will ever know
    // about who he is talking to comes out of this preamble, and the
    // DH1/DH2 legs below consume `alice_identity_ecdh_public` — so that
    // key must be provably the one belonging to the identity named by
    // `alice_identity`, checked before it is used for any DH.
    if !verify_identity_ecdh_binding(&preamble.alice_identity_keys()) {
        return Err(RatchetError::InvalidBundleSignature);
    }

    let dh1 = brainpool512_diffie_hellman(my_signed_pre_key_ecdh, &preamble.alice_identity_ecdh_public)?;
    let dh2 = brainpool512_diffie_hellman(&my_identity.ecdh, &preamble.alice_ephemeral_ecdh_public)?;
    let dh3 = brainpool512_diffie_hellman(my_signed_pre_key_ecdh, &preamble.alice_ephemeral_ecdh_public)?;
    let kem_ss_signed = ml_kem_decapsulate(my_signed_pre_key_kem, &preamble.kem_ciphertext_signed)?;

    // Zeroizing-wrapped: this Vec is the concatenated raw shared-secret
    // IKM itself, not a derived output — every constituent DH/KEM
    // secret is already Zeroizing on its own, but copying them into a
    // plain Vec would leave that copy unwiped. (Fixed here after Task
    // 4's review caught the identical bug in that task's sample code.)
    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(3 * 64 + 32 + 32));
    ikm.extend_from_slice(&*dh1);
    ikm.extend_from_slice(&*dh2);
    ikm.extend_from_slice(&*dh3);
    ikm.extend_from_slice(&*kem_ss_signed);

    if let (Some(ct), Some((_otpk_ecdh, otpk_kem))) =
        (&preamble.kem_ciphertext_onetime, my_one_time_pre_key)
    {
        let ss = ml_kem_decapsulate(otpk_kem, ct)?;
        ikm.extend_from_slice(&*ss);
    }

    let my_identity_pub = my_identity.public_keys();
    let bob_identity_bytes =
        identity_transcript_bytes(&my_identity_pub.verifying, &my_identity_pub.ecdh_public);
    let alice_identity_bytes = identity_transcript_bytes(
        &preamble.alice_identity,
        &preamble.alice_identity_ecdh_public,
    );

    let mut root_key = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    derive_key(
        &ikm,
        X3DH_DOMAIN_LABEL,
        preamble.protocol_version,
        &alice_identity_bytes,
        &bob_identity_bytes,
        root_key.as_mut(),
    )?;

    Ok(root_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf_chain;
    use crate::prekey::{generate_one_time_pre_key, generate_signed_pre_key, IdentityKeyPair, PreKeyBundle};
    use aegis_crypto::version::ProtocolVersion;

    fn bob_bundle_and_identity() -> (PreKeyBundle, IdentityKeyPair) {
        let bob = IdentityKeyPair::generate();
        let (signed_pre_key, _ecdh_priv, _kem_priv) = generate_signed_pre_key(&bob);
        let bundle = PreKeyBundle {
            identity: bob.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };
        (bundle, bob)
    }

    #[test]
    fn initiate_produces_a_root_key_and_preamble() {
        let alice = IdentityKeyPair::generate();
        let (bob_bundle, _bob) = bob_bundle_and_identity();

        let (root_key, preamble, alice_ephemeral_public) =
            initiate_x3dh(&alice, &bob_bundle, ProtocolVersion::V1).unwrap();

        assert_ne!(*root_key, [0u8; kdf_chain::ROOT_KEY_LEN]);
        assert_eq!(preamble.alice_ephemeral_ecdh_public, alice_ephemeral_public);
        assert!(preamble.used_one_time_pre_key_id.is_none());
    }

    #[test]
    fn preamble_round_trips_through_wire_bytes() {
        let alice = IdentityKeyPair::generate();
        let (bob_bundle, _bob) = bob_bundle_and_identity();
        let (_root_key, preamble, _) = initiate_x3dh(&alice, &bob_bundle, ProtocolVersion::V1).unwrap();

        let decoded = X3DHPreamble::from_bytes(&preamble.to_bytes()).unwrap();
        assert_eq!(decoded.alice_ephemeral_ecdh_public, preamble.alice_ephemeral_ecdh_public);
        assert_eq!(decoded.kem_ciphertext_signed, preamble.kem_ciphertext_signed);
        assert_eq!(decoded.used_one_time_pre_key_id, preamble.used_one_time_pre_key_id);
    }

    #[test]
    fn rejects_a_bundle_with_an_invalid_signature() {
        let alice = IdentityKeyPair::generate();
        let (mut bob_bundle, _bob) = bob_bundle_and_identity();
        bob_bundle.signed_pre_key.ecdh_public[0] ^= 0xFF; // now the signature no longer matches

        assert_eq!(
            initiate_x3dh(&alice, &bob_bundle, ProtocolVersion::V1).unwrap_err(),
            RatchetError::InvalidBundleSignature,
        );
    }

    #[test]
    fn both_sides_derive_the_same_root_key() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob);
        let bundle = PreKeyBundle {
            identity: bob.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };

        let (alice_root_key, preamble, _alice_ephemeral) =
            initiate_x3dh(&alice, &bundle, ProtocolVersion::V1).unwrap();

        let bob_root_key =
            respond_to_x3dh(&bob, &bob_spk_ecdh, &bob_spk_kem, None, &preamble).unwrap();

        assert_eq!(*alice_root_key, *bob_root_key);
    }

    #[test]
    fn both_sides_agree_when_a_one_time_pre_key_is_used() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob);
        let (one_time_pre_key, bob_otpk_ecdh, bob_otpk_kem) = generate_one_time_pre_key(1);
        let bundle = PreKeyBundle {
            identity: bob.public_keys(),
            signed_pre_key,
            one_time_pre_key: Some(one_time_pre_key),
        };

        let (alice_root_key, preamble, _) = initiate_x3dh(&alice, &bundle, ProtocolVersion::V1).unwrap();
        assert!(preamble.used_one_time_pre_key_id.is_some());

        let bob_root_key = respond_to_x3dh(
            &bob,
            &bob_spk_ecdh,
            &bob_spk_kem,
            Some((&bob_otpk_ecdh, &bob_otpk_kem)),
            &preamble,
        )
        .unwrap();

        assert_eq!(*alice_root_key, *bob_root_key);
    }

    #[test]
    fn initiate_rejects_a_bundle_whose_identity_ecdh_key_is_not_bound() {
        // Finding C3, initiator side: a bundle that pairs a real
        // party's verifying keys with someone else's identity ECDH key
        // must be refused before any DH leg consumes that key.
        let alice = IdentityKeyPair::generate();
        let attacker = IdentityKeyPair::generate();
        let (mut bob_bundle, _bob) = bob_bundle_and_identity();
        bob_bundle.identity.ecdh_public = attacker.public_keys().ecdh_public;

        assert_eq!(
            initiate_x3dh(&alice, &bob_bundle, ProtocolVersion::V1).unwrap_err(),
            RatchetError::InvalidBundleSignature,
        );
    }

    #[test]
    fn responder_rejects_a_preamble_claiming_someone_elses_identity() {
        // Finding C3, the actual impersonation attack, responder side.
        //
        // Mallory runs a perfectly well-formed handshake against Bob's
        // real bundle using her OWN identity ECDH key, ephemeral key
        // and KEM ciphertexts — then rewrites only the *claimed*
        // identity in the preamble to Alice's real dual verifying key.
        // Every DH/KEM leg still agrees internally and both sides used
        // to derive the same root key, so Bob decrypted successfully
        // and believed he was talking to Alice.
        //
        // Bob must now refuse: Mallory cannot produce Alice's
        // self-signature over Mallory's own ECDH public key.
        let alice = IdentityKeyPair::generate();
        let mallory = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob);
        let bundle = PreKeyBundle {
            identity: bob.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };

        let (_mallory_root_key, mut forged_preamble, _) =
            initiate_x3dh(&mallory, &bundle, ProtocolVersion::V1).unwrap();
        forged_preamble.alice_identity = alice.public_keys().verifying;

        assert_eq!(
            respond_to_x3dh(&bob, &bob_spk_ecdh, &bob_spk_kem, None, &forged_preamble).unwrap_err(),
            RatchetError::InvalidBundleSignature,
            "a preamble pairing Alice's verifying key with Mallory's DH key must be rejected",
        );
    }

    #[test]
    fn a_preamble_replaying_a_victims_bound_identity_diverges_on_the_root_key() {
        // The other half of finding C3's fix: suppose Mallory instead
        // copies Alice's identity ECDH key *and* Alice's genuine
        // binding signature (both are public), so the binding check
        // passes. She still does not hold Alice's private identity
        // scalar, so the DH1/DH2 legs she computes cannot match the
        // ones Bob computes — the root keys must provably diverge, and
        // nothing Mallory sends can then be decrypted by Bob.
        let alice = IdentityKeyPair::generate();
        let mallory = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob);
        let bundle = PreKeyBundle {
            identity: bob.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };

        let (mallory_root_key, mut forged_preamble, _) =
            initiate_x3dh(&mallory, &bundle, ProtocolVersion::V1).unwrap();
        let alice_public = alice.public_keys();
        forged_preamble.alice_identity = alice_public.verifying.clone();
        forged_preamble.alice_identity_ecdh_public = alice_public.ecdh_public;
        forged_preamble.alice_identity_ecdh_signature = alice_public.ecdh_public_signature;

        // The binding itself now verifies (it is Alice's real, public
        // signature over her real, public key) so Bob proceeds...
        let bob_root_key =
            respond_to_x3dh(&bob, &bob_spk_ecdh, &bob_spk_kem, None, &forged_preamble).unwrap();

        // ...but derives a root key Mallory cannot know, because DH1
        // used Alice's identity key that Mallory has no private half
        // of, and because the identity ECDH keys are now bound into the
        // KDF's `info` transcript as well.
        assert_ne!(*mallory_root_key, *bob_root_key);
    }

    #[test]
    fn root_key_is_bound_to_the_identity_ecdh_keys_not_just_the_verifying_keys() {
        // Direct check of the transcript-binding half of finding C3's
        // fix: two handshakes identical except for one party's
        // long-term identity ECDH key must derive different root keys.
        let alice = IdentityKeyPair::generate();
        let (bundle, _bob) = bob_bundle_and_identity();

        let (root_a, preamble, _) = initiate_x3dh(&alice, &bundle, ProtocolVersion::V1).unwrap();

        // Re-derive with the same IKM inputs but a different claimed
        // identity ECDH key in the transcript.
        let other = IdentityKeyPair::generate();
        let mut root_b = Zeroizing::new([0u8; ROOT_KEY_LEN]);
        let alice_bytes = identity_transcript_bytes(
            &preamble.alice_identity,
            &other.public_keys().ecdh_public,
        );
        let bob_bytes = identity_transcript_bytes(
            &bundle.identity.verifying,
            &bundle.identity.ecdh_public,
        );
        // Any IKM works here; the point is the `info` transcript.
        derive_key(
            b"same-ikm-either-way",
            X3DH_DOMAIN_LABEL,
            ProtocolVersion::V1 as u8,
            &alice_bytes,
            &bob_bytes,
            root_b.as_mut(),
        )
        .unwrap();

        let mut root_c = Zeroizing::new([0u8; ROOT_KEY_LEN]);
        let alice_bytes_real = identity_transcript_bytes(
            &preamble.alice_identity,
            &preamble.alice_identity_ecdh_public,
        );
        derive_key(
            b"same-ikm-either-way",
            X3DH_DOMAIN_LABEL,
            ProtocolVersion::V1 as u8,
            &alice_bytes_real,
            &bob_bytes,
            root_c.as_mut(),
        )
        .unwrap();

        assert_ne!(
            *root_b, *root_c,
            "swapping only the identity ECDH key must change the derived key",
        );
        assert_ne!(*root_a, *root_c, "different IKM must also change it");

        // Structural check, so this test is not merely asserting that a
        // KDF is a KDF: the transcript must actually *contain* the
        // identity ECDH key, and be exactly the three fixed-length
        // components (which is what makes the concatenation injective
        // without any internal framing).
        assert_eq!(
            alice_bytes_real.len(),
            ED25519_PUBLIC_KEY_LEN + ML_DSA_87_PUBLIC_KEY_LEN + ECDH_PUBLIC_KEY_LEN,
        );
        assert!(
            alice_bytes_real
                .windows(ECDH_PUBLIC_KEY_LEN)
                .any(|w| w == preamble.alice_identity_ecdh_public),
            "the identity ECDH key must be part of the KDF transcript (finding C3)",
        );
        assert!(
            alice_bytes_real.starts_with(&preamble.alice_identity.ed25519),
            "the verifying keys must still lead the transcript",
        );
    }

    #[test]
    fn a_full_handshake_agrees_only_when_both_identity_transcripts_match() {
        // End-to-end complement to the unit check above: a genuine
        // handshake still agrees on both sides *with* the identity ECDH
        // keys in the transcript, so the C3 binding is additive, not a
        // change that quietly breaks agreement.
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob);
        let bundle = PreKeyBundle {
            identity: bob.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };

        let (alice_root, preamble, _) =
            initiate_x3dh(&alice, &bundle, ProtocolVersion::V1).unwrap();
        let bob_root =
            respond_to_x3dh(&bob, &bob_spk_ecdh, &bob_spk_kem, None, &preamble).unwrap();
        assert_eq!(*alice_root, *bob_root);

        // And the preamble carries a binding that verifies against the
        // identity it claims -- the thing `respond_to_x3dh` checks.
        assert!(verify_identity_ecdh_binding(&IdentityKeys {
            verifying: preamble.alice_identity.clone(),
            ecdh_public: preamble.alice_identity_ecdh_public,
            ecdh_public_signature: preamble.alice_identity_ecdh_signature.clone(),
        }));
        assert_eq!(
            preamble.alice_identity_ecdh_public,
            alice.public_keys().ecdh_public,
        );
    }

    #[test]
    fn a_third_party_derives_a_different_root_key() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let mallory = IdentityKeyPair::generate();
        let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob);
        let bundle = PreKeyBundle {
            identity: bob.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };

        let (alice_root_key, _preamble, _) = initiate_x3dh(&alice, &bundle, ProtocolVersion::V1).unwrap();
        let (_mallory_root_key, mallory_preamble, _) =
            initiate_x3dh(&mallory, &bundle, ProtocolVersion::V1).unwrap();

        let bob_root_key_from_mallory =
            respond_to_x3dh(&bob, &bob_spk_ecdh, &bob_spk_kem, None, &mallory_preamble).unwrap();

        assert_ne!(*alice_root_key, *bob_root_key_from_mallory);
    }
}
