//! The Double Ratchet's own root-key and chain-key KDFs (`KDF_RK`,
//! `KDF_CK`), adapted from Signal's Double Ratchet spec
//! (<https://signal.org/docs/specifications/doubleratchet/#external-functions>,
//! HMAC-SHA256 there, HMAC-SHA512 here for consistency with the rest
//! of `aegis-crypto`). Distinct from `aegis_crypto::kdf::derive_key`:
//! that function hardcodes HKDF salt to `None`, but `KDF_RK` requires
//! `salt = root_key` — see this plan's Global Constraints.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

/// Byte length of a ratchet root key.
pub const ROOT_KEY_LEN: usize = 64;
/// Byte length of a ratchet chain key.
pub const CHAIN_KEY_LEN: usize = 64;
/// Byte length of a derived message key (truncated for AES-256-GCM /
/// ChaCha20-Poly1305 keying).
pub const MESSAGE_KEY_LEN: usize = 32;

const RK_DOMAIN_LABEL: &[u8] = b"AEGIS-RATCHET-RK-v1";

/// The Double Ratchet's root-key KDF: advances `root_key` using a
/// fresh hybrid (ML-KEM-1024 + brainpool512r1) shared secret, per
/// design §3.1. Returns `(new_root_key, chain_key)`.
pub fn kdf_rk(
    root_key: &[u8; ROOT_KEY_LEN],
    hybrid_shared_secret: &[u8],
) -> (Zeroizing<[u8; ROOT_KEY_LEN]>, Zeroizing<[u8; CHAIN_KEY_LEN]>) {
    let hk = Hkdf::<Sha512>::new(Some(root_key), hybrid_shared_secret);
    let mut output = Zeroizing::new([0u8; ROOT_KEY_LEN + CHAIN_KEY_LEN]);
    hk.expand(RK_DOMAIN_LABEL, output.as_mut())
        .expect("128-byte expansion is far under HKDF-SHA512's 16320-byte limit");

    let mut new_root_key = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    let mut chain_key = Zeroizing::new([0u8; CHAIN_KEY_LEN]);
    new_root_key.copy_from_slice(&output[..ROOT_KEY_LEN]);
    chain_key.copy_from_slice(&output[ROOT_KEY_LEN..]);
    (new_root_key, chain_key)
}

/// The Double Ratchet's chain-key KDF: advances `chain_key` by one
/// message, per design §3.1. Returns `(new_chain_key, message_key)`.
pub fn kdf_ck(
    chain_key: &[u8; CHAIN_KEY_LEN],
) -> (Zeroizing<[u8; CHAIN_KEY_LEN]>, Zeroizing<[u8; MESSAGE_KEY_LEN]>) {
    let mut mac_for_chain =
        Hmac::<Sha512>::new_from_slice(chain_key).expect("HMAC-SHA512 accepts any key length");
    mac_for_chain.update(&[0x02]);
    let chain_result = mac_for_chain.finalize().into_bytes();
    let mut new_chain_key = Zeroizing::new([0u8; CHAIN_KEY_LEN]);
    new_chain_key.copy_from_slice(&chain_result);

    let mut mac_for_message =
        Hmac::<Sha512>::new_from_slice(chain_key).expect("HMAC-SHA512 accepts any key length");
    mac_for_message.update(&[0x01]);
    let message_result = mac_for_message.finalize().into_bytes();
    let mut message_key = Zeroizing::new([0u8; MESSAGE_KEY_LEN]);
    message_key.copy_from_slice(&message_result[..MESSAGE_KEY_LEN]);

    (new_chain_key, message_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_rk_is_deterministic() {
        let root = [0x11u8; ROOT_KEY_LEN];
        let (rk1, ck1) = kdf_rk(&root, b"shared-secret");
        let (rk2, ck2) = kdf_rk(&root, b"shared-secret");
        assert_eq!(*rk1, *rk2);
        assert_eq!(*ck1, *ck2);
    }

    #[test]
    fn kdf_rk_new_root_key_differs_from_input_and_chain_key() {
        let root = [0x11u8; ROOT_KEY_LEN];
        let (new_root, chain_key) = kdf_rk(&root, b"shared-secret");
        assert_ne!(*new_root, root, "KDF_RK must not just echo its input");
        assert_ne!(&new_root[..], &chain_key[..], "root and chain outputs must differ");
    }

    #[test]
    fn kdf_rk_different_shared_secrets_diverge() {
        let root = [0x11u8; ROOT_KEY_LEN];
        let (rk_a, ck_a) = kdf_rk(&root, b"secret-a");
        let (rk_b, ck_b) = kdf_rk(&root, b"secret-b");
        assert_ne!(*rk_a, *rk_b);
        assert_ne!(*ck_a, *ck_b);
    }

    #[test]
    fn kdf_ck_new_chain_key_differs_from_message_key() {
        let chain = [0x22u8; CHAIN_KEY_LEN];
        let (new_chain, message_key) = kdf_ck(&chain);
        assert_ne!(&new_chain[..], &message_key[..]);
        assert_ne!(*new_chain, chain, "KDF_CK must not just echo its input");
    }

    #[test]
    fn kdf_ck_advances_differently_each_call() {
        let chain0 = [0x22u8; CHAIN_KEY_LEN];
        let (chain1, mk0) = kdf_ck(&chain0);
        let (chain2, mk1) = kdf_ck(&chain1);
        assert_ne!(*chain1, *chain2, "each chain step must move the chain forward");
        assert_ne!(*mk0, *mk1, "each step's message key must be unique");
    }
}
