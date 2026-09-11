//! GDPR Art. 20 export: every readable record across the given
//! namespaces, as signed, passphrase-encrypted JSON. See design spec
//! Section 4.

use crate::error::VaultError;
use crate::vault::Vault;
use aegis_crypto::aead::{decrypt, encrypt, AeadAlgorithm};
use aegis_crypto::passphrase::derive_master_key_production;
use aegis_crypto::signature::{verify_dual, DualKeyPair, DualSignature};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct SignedExport {
    /// namespace -> (key -> base64 plaintext)
    records: BTreeMap<String, BTreeMap<String, String>>,
    signer_ed25519_pub: String,
    signer_ml_dsa87_pub: String,
    ed25519_sig: String,
    ml_dsa87_sig: String,
}

const ARGON2_SALT_LEN: usize = 16;
const AEAD_NONCE_LEN: usize = 12;

/// Serializes every readable record in `namespaces` to JSON, signs
/// that JSON with `signing_key`, bundles signature and signer public
/// keys into one self-verifiable structure, then encrypts the whole
/// thing under an Argon2id key derived from `passphrase`.
///
/// Output framing: `argon2_salt (16 bytes) || aead_nonce (12 bytes) ||
/// ciphertext`.
pub(crate) fn export_vault(
    vault: &Vault,
    namespaces: &[&str],
    signing_key: &DualKeyPair,
    passphrase: &str,
) -> Result<Vec<u8>, VaultError> {
    let mut records = BTreeMap::new();
    for &namespace in namespaces {
        let mut ns_records = BTreeMap::new();
        for key in vault.list_keys(namespace)? {
            if let Some(plaintext) = vault.get(namespace, &key)? {
                // `plaintext` (`Zeroizing<Vec<u8>>`) wipes on drop at
                // the end of this iteration; the base64 copy below is
                // the record's actual export payload, not an
                // incidental extra copy, so it is not itself wiped.
                ns_records.insert(key, B64.encode(&*plaintext));
            }
        }
        records.insert(namespace.to_string(), ns_records);
    }

    let unsigned_json = serde_json::to_vec(&records)
        .map_err(|e| VaultError::StorageCorrupted(format!("export serialization failed: {e}")))?;
    let signature = signing_key.sign(&unsigned_json);

    let signed = SignedExport {
        records,
        signer_ed25519_pub: B64.encode(signing_key.ed25519_public_bytes()),
        signer_ml_dsa87_pub: B64.encode(signing_key.ml_dsa87_public_bytes()),
        ed25519_sig: B64.encode(signature.ed25519),
        ml_dsa87_sig: B64.encode(&signature.ml_dsa87),
    };
    // The signed JSON is the export's plaintext payload prior to
    // encryption below — wrapped in `Zeroizing` so it doesn't linger
    // in memory unencrypted beyond this function's lifetime.
    let signed_json = Zeroizing::new(serde_json::to_vec(&signed).map_err(|e| {
        VaultError::StorageCorrupted(format!("export serialization failed: {e}"))
    })?);

    let mut salt = [0u8; ARGON2_SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|_| VaultError::StorageCorrupted("OS RNG failure generating export salt".into()))?;
    let mut export_key = Zeroizing::new([0u8; 32]);
    derive_master_key_production(passphrase.as_bytes(), &salt, b"", b"", export_key.as_mut())
        .map_err(|e| VaultError::StorageCorrupted(format!("Argon2id failed: {e}")))?;

    let mut nonce = [0u8; AEAD_NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|_| VaultError::StorageCorrupted("OS RNG failure generating export nonce".into()))?;
    let ciphertext = encrypt(AeadAlgorithm::Aes256Gcm, &export_key, &nonce, b"", &signed_json)
        .map_err(|_| VaultError::StorageCorrupted("failed to seal export".into()))?;

    let mut out = Vec::with_capacity(ARGON2_SALT_LEN + AEAD_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts an export produced by `export_vault` and independently
/// re-verifies its dual signature — used by this module's own
/// round-trip test, and usable by any future recipient-side tooling
/// that wants to verify a GDPR export outside this crate.
///
/// `#[allow(dead_code)]`: this is `pub(crate)` per the design spec's
/// public interface for this module (Section 4/6), not private to the
/// test module below — but nothing in the crate's non-test code calls
/// it yet, since verifying an export is the recipient's job, not this
/// crate's. Kept `pub(crate)` rather than test-only (`#[cfg(test)]`)
/// so it stays available to any future `Vault`-side tooling without a
/// visibility change.
#[allow(dead_code)]
pub(crate) fn decrypt_and_verify_export(
    export_bytes: &[u8],
    passphrase: &str,
) -> Result<(serde_json::Value, bool), VaultError> {
    if export_bytes.len() < ARGON2_SALT_LEN + AEAD_NONCE_LEN {
        return Err(VaultError::StorageCorrupted("export is too short".into()));
    }
    let (salt, rest) = export_bytes.split_at(ARGON2_SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(AEAD_NONCE_LEN);
    let nonce: [u8; AEAD_NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| VaultError::StorageCorrupted("malformed export nonce".into()))?;

    let mut export_key = Zeroizing::new([0u8; 32]);
    derive_master_key_production(passphrase.as_bytes(), salt, b"", b"", export_key.as_mut())
        .map_err(|e| VaultError::StorageCorrupted(format!("Argon2id failed: {e}")))?;

    // The decrypted signed JSON is sensitive plaintext until the
    // signature below is verified (and, being an export of vault
    // contents, arguably even after) — kept `Zeroizing` for the
    // duration of this function.
    let signed_json = Zeroizing::new(
        decrypt(AeadAlgorithm::Aes256Gcm, &export_key, &nonce, b"", ciphertext)
            .map_err(|_| VaultError::StorageCorrupted("wrong passphrase or tampered export".into()))?,
    );

    let signed: SignedExport = serde_json::from_slice(&signed_json)
        .map_err(|e| VaultError::StorageCorrupted(format!("malformed export JSON: {e}")))?;

    let records_json = serde_json::to_vec(&signed.records)
        .map_err(|e| VaultError::StorageCorrupted(format!("re-serialization failed: {e}")))?;

    let ed25519_pub: [u8; 32] = B64
        .decode(&signed.signer_ed25519_pub)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| VaultError::StorageCorrupted("malformed signer ed25519 key".into()))?;
    let ml_dsa87_pub = B64
        .decode(&signed.signer_ml_dsa87_pub)
        .map_err(|_| VaultError::StorageCorrupted("malformed signer ml-dsa87 key".into()))?;
    let ed25519_sig: [u8; 64] = B64
        .decode(&signed.ed25519_sig)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| VaultError::StorageCorrupted("malformed ed25519 signature".into()))?;
    let ml_dsa87_sig = B64
        .decode(&signed.ml_dsa87_sig)
        .map_err(|_| VaultError::StorageCorrupted("malformed ml-dsa87 signature".into()))?;

    let valid = verify_dual(
        &ed25519_pub,
        &ml_dsa87_pub,
        &records_json,
        &DualSignature {
            ed25519: ed25519_sig,
            ml_dsa87: ml_dsa87_sig,
        },
    );

    let records_value = serde_json::to_value(&signed.records)
        .map_err(|e| VaultError::StorageCorrupted(format!("value conversion failed: {e}")))?;
    Ok((records_value, valid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MockKeyStore;
    use crate::vault::Vault;
    use std::env::temp_dir;

    fn temp_db_path(name: &str) -> std::path::PathBuf {
        temp_dir().join(format!("aegis-vault-test-{name}-{}.db", std::process::id()))
    }

    #[test]
    fn export_round_trips_and_verifies() {
        let path = temp_db_path("export-round-trip");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault =
            Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        vault.put("messages", "msg-1", b"hello export").unwrap();
        vault.put("contacts", "alice", b"alice's data").unwrap();

        let signing_key = DualKeyPair::generate();
        let export_bytes =
            export_vault(&vault, &["messages", "contacts"], &signing_key, "correct horse").unwrap();

        let (records, valid) = decrypt_and_verify_export(&export_bytes, "correct horse").unwrap();
        assert!(valid, "signature must verify");
        assert_eq!(
            records["messages"]["msg-1"],
            B64.encode(b"hello export")
        );
        assert_eq!(
            records["contacts"]["alice"],
            B64.encode(b"alice's data")
        );

        drop(vault);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn export_with_wrong_passphrase_fails_to_decrypt() {
        let path = temp_db_path("export-wrong-pass");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault =
            Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        vault.put("messages", "msg-1", b"secret").unwrap();

        let signing_key = DualKeyPair::generate();
        let export_bytes =
            export_vault(&vault, &["messages"], &signing_key, "right passphrase").unwrap();

        let result = decrypt_and_verify_export(&export_bytes, "wrong passphrase");
        assert!(result.is_err());

        drop(vault);
        std::fs::remove_file(&path).unwrap();
    }
}
