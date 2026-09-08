//! PQ-X3DH handshake (design §2). Extends Signal's X3DH
//! (<https://signal.org/docs/specifications/x3dh/>) from a 3-DH
//! combiner to a hybrid 4-leg combiner: the three classical DH legs
//! are unchanged, plus one ML-KEM-1024 encapsulation leg (two, if the
//! bundle includes a one-time pre-key).

use crate::error::RatchetError;
use crate::kdf_chain::ROOT_KEY_LEN;
use crate::prekey::{
    verify_signed_pre_key, ByteCursor, IdentityKeyPair, PreKeyBundle, DualVerifyingKey,
    ECDH_PUBLIC_KEY_LEN, ED25519_PUBLIC_KEY_LEN, KEM_CIPHERTEXT_LEN, ML_DSA_87_PUBLIC_KEY_LEN,
};
use aegis_crypto::ecdh::{brainpool512_diffie_hellman, Brainpool512SecretKey};
use aegis_crypto::kdf::derive_key;
use aegis_crypto::kem::{ml_kem_decapsulate, ml_kem_encapsulate, MlKem1024KeyPair};
use aegis_crypto::version::ProtocolVersion;
use zeroize::Zeroizing;

const X3DH_DOMAIN_LABEL: &[u8] = b"AEGIS-X3DH-v1";

/// Everything a X3DH initial handshake message carries except the
/// first actual ciphertext (Task 6 combines this with a
/// `RatchetMessage` for transmission).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X3DHPreamble {
    pub protocol_version: u8,
    pub alice_identity: DualVerifyingKey,
    pub alice_identity_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
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
            alice_ephemeral_ecdh_public,
            kem_ciphertext_signed,
            used_one_time_pre_key_id,
            kem_ciphertext_onetime,
        })
    }
}

/// Compute Alice's X3DH shared secret and preamble against Bob's
/// `peer_bundle`. Returns `(root_key, preamble, alice_ephemeral_ecdh_public)`
/// — the caller (Task 6) uses `alice_ephemeral_ecdh_public` again as
/// Alice's first ratchet public key, so it's returned directly rather
/// than making Task 6 re-parse it out of `preamble`.
///
/// # Errors
///
/// Returns [`RatchetError::InvalidBundleSignature`] if
/// `peer_bundle.signed_pre_key`'s signature does not verify against
/// `peer_bundle.identity`. Propagates [`RatchetError::Crypto`] from
/// malformed key material.
pub fn initiate_x3dh(
    my_identity: &IdentityKeyPair,
    peer_bundle: &PreKeyBundle,
    protocol_version: ProtocolVersion,
) -> Result<(Zeroizing<[u8; ROOT_KEY_LEN]>, X3DHPreamble, [u8; ECDH_PUBLIC_KEY_LEN]), RatchetError> {
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
    let mut alice_identity_bytes = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ML_DSA_87_PUBLIC_KEY_LEN);
    alice_identity_bytes.extend_from_slice(&alice_identity_pub.verifying.ed25519);
    alice_identity_bytes.extend_from_slice(&alice_identity_pub.verifying.ml_dsa87);
    let mut bob_identity_bytes = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ML_DSA_87_PUBLIC_KEY_LEN);
    bob_identity_bytes.extend_from_slice(&peer_bundle.identity.verifying.ed25519);
    bob_identity_bytes.extend_from_slice(&peer_bundle.identity.verifying.ml_dsa87);

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
/// Propagates [`RatchetError::Crypto`] from malformed key material.
/// Does not itself re-verify a bundle signature (Bob is answering his
/// own published bundle, not re-checking it) — signature verification
/// happens only on the initiating side, against the bundle it received
/// (Task 4).
pub fn respond_to_x3dh(
    my_identity: &IdentityKeyPair,
    my_signed_pre_key_ecdh: &Brainpool512SecretKey,
    my_signed_pre_key_kem: &MlKem1024KeyPair,
    my_one_time_pre_key: Option<(&Brainpool512SecretKey, &MlKem1024KeyPair)>,
    preamble: &X3DHPreamble,
) -> Result<Zeroizing<[u8; ROOT_KEY_LEN]>, RatchetError> {
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
    let mut bob_identity_bytes = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ML_DSA_87_PUBLIC_KEY_LEN);
    bob_identity_bytes.extend_from_slice(&my_identity_pub.verifying.ed25519);
    bob_identity_bytes.extend_from_slice(&my_identity_pub.verifying.ml_dsa87);
    let mut alice_identity_bytes = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ML_DSA_87_PUBLIC_KEY_LEN);
    alice_identity_bytes.extend_from_slice(&preamble.alice_identity.ed25519);
    alice_identity_bytes.extend_from_slice(&preamble.alice_identity.ml_dsa87);

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
