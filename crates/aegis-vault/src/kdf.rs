//! Internal domain-separated HKDF-SHA512 derivations from the Vault
//! Master Key. See design spec Section 1 for why this crate uses its
//! own tiny KDF wrapper instead of `aegis_crypto::kdf::derive_key`.

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

fn derive(vmk: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha512>::new(None, vmk);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(label, out.as_mut())
        .expect("32 bytes is within HKDF-SHA512's output limit");
    out
}

/// The key SQLCipher's page cipher is keyed with (via `PRAGMA key`).
pub(crate) fn derive_sqlcipher_key(vmk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    derive(vmk, b"AEGIS-VAULT-SQLCIPHER-KEY-v1")
}

/// The key that wraps (encrypts) each record's per-record DEK. Not
/// yet called outside tests — lands with per-record DEK wrapping in
/// a later task.
#[allow(dead_code)]
pub(crate) fn derive_dek_wrap_key(vmk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    derive(vmk, b"AEGIS-VAULT-DEK-WRAP-v1")
}

/// The key that encrypts the `vault_meta` canary value.
pub(crate) fn derive_canary_key(vmk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    derive(vmk, b"AEGIS-VAULT-CANARY-v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_vmk_is_deterministic() {
        let vmk = [0x42u8; 32];
        assert_eq!(*derive_sqlcipher_key(&vmk), *derive_sqlcipher_key(&vmk));
    }

    #[test]
    fn different_labels_produce_different_keys() {
        let vmk = [0x42u8; 32];
        let sqlcipher = derive_sqlcipher_key(&vmk);
        let dek_wrap = derive_dek_wrap_key(&vmk);
        let canary = derive_canary_key(&vmk);
        assert_ne!(*sqlcipher, *dek_wrap);
        assert_ne!(*sqlcipher, *canary);
        assert_ne!(*dek_wrap, *canary);
    }

    #[test]
    fn different_vmks_produce_different_keys() {
        let vmk_a = [0x11u8; 32];
        let vmk_b = [0x22u8; 32];
        assert_ne!(*derive_sqlcipher_key(&vmk_a), *derive_sqlcipher_key(&vmk_b));
    }

    #[test]
    fn derived_key_differs_from_raw_vmk() {
        let vmk = [0x42u8; 32];
        assert_ne!(*derive_sqlcipher_key(&vmk), vmk);
    }
}
