//! SQLCipher connection bootstrap: schema creation, the VMK canary,
//! and the specific ordering that avoids the chicken-and-egg problem
//! of needing the SQLCipher key before any table (including one that
//! might otherwise have stored it) can be read. See design spec
//! Section 3.

use crate::error::VaultError;
use crate::kdf::{derive_canary_key, derive_sqlcipher_key};
use aegis_crypto::aead::{decrypt, encrypt, AeadAlgorithm};
use rusqlite::Connection;
use std::path::Path;
use zeroize::Zeroizing;

// `create_new`/`open_existing` (and everything only they call — the
// consts below, `hex_encode`, `set_sqlcipher_key`) have no caller
// within this task: Task 5 only establishes the bootstrap functions
// themselves. Task 6 (`Vault::open`) is what wires them in. Until
// then the non-test build's dead-code pass can't see the `#[cfg(test)]`
// module below that already exercises them, so it flags the whole
// chain. `#[allow(dead_code)]` is scoped to exactly these items so an
// accidental future dead function elsewhere in this file would still
// be caught. Mirrors the same situation documented in `kdf.rs`.
#[allow(dead_code)]
const CANARY_PLAINTEXT: &[u8] = b"AEGIS-VAULT-CANARY-v1";
#[allow(dead_code)]
const CANARY_NONCE: [u8; 12] = [0u8; 12]; // fixed: one canary row, one key, written exactly once per vault.

#[allow(dead_code)]
const SCHEMA: &str = "
CREATE TABLE vault_meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE vault_records (
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    wrapped_dek BLOB,
    dek_nonce   BLOB,
    ciphertext  BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (namespace, key)
);
";

/// Hex-encode `bytes` into a `Zeroizing` buffer. `rusqlite`'s generic
/// `pragma_update` only ever formats `Integer`/`Real`/`Text` `ToSql`
/// values into the PRAGMA statement text — a raw `Blob` value (what a
/// 32-byte key naturally is) is rejected with `SQLITE_MISUSE`. SQLCipher's
/// own documented workaround is to pass the raw key as a hex-encoded
/// blob literal — `PRAGMA key = "x'<hex>'"` — which we build by hand
/// here, keeping every intermediate buffer `Zeroizing` since each one
/// transiently holds the key material.
#[allow(dead_code)]
fn hex_encode(bytes: &[u8]) -> Zeroizing<String> {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for &b in bytes {
        out.push(HEX_DIGITS[(b >> 4) as usize] as char);
        out.push(HEX_DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

#[allow(dead_code)]
fn set_sqlcipher_key(conn: &Connection, vmk: &[u8; 32]) -> Result<(), VaultError> {
    let sqlcipher_key = derive_sqlcipher_key(vmk);
    let hex_key = hex_encode(sqlcipher_key.as_slice());
    let key_pragma: Zeroizing<String> =
        Zeroizing::new(format!("PRAGMA key = \"x'{}'\"", hex_key.as_str()));
    conn.execute_batch(key_pragma.as_str())?;
    Ok(())
}

/// Bootstrap a brand-new vault: open (creating) the file, key it,
/// create the schema, and write the canary.
#[allow(dead_code)]
pub(crate) fn create_new(db_path: &Path, vmk: &[u8; 32]) -> Result<Connection, VaultError> {
    let conn = Connection::open(db_path)?;
    set_sqlcipher_key(&conn, vmk)?;
    conn.execute_batch(SCHEMA)?;

    let canary_key = derive_canary_key(vmk);
    let canary_ct = encrypt(
        AeadAlgorithm::Aes256Gcm,
        &canary_key,
        &CANARY_NONCE,
        b"",
        CANARY_PLAINTEXT,
    )
    .map_err(|_| VaultError::StorageCorrupted("failed to seal canary".into()))?;
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES ('canary', ?1)",
        [canary_ct],
    )?;
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES ('schema_version', ?1)",
        [vec![1u8]],
    )?;

    Ok(conn)
}

/// Bootstrap an existing vault: open the file, key it with the
/// caller's loaded VMK, and verify the canary decrypts. This is the
/// zero-fallback-adjacent correctness check for the VMK itself — see
/// `VaultError::VmkCanaryMismatch`.
#[allow(dead_code)]
pub(crate) fn open_existing(db_path: &Path, vmk: &[u8; 32]) -> Result<Connection, VaultError> {
    let conn = Connection::open(db_path)?;
    set_sqlcipher_key(&conn, vmk)?;

    let canary_ct: Vec<u8> = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'canary'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| VaultError::VmkCanaryMismatch)?;

    let canary_key = derive_canary_key(vmk);
    let plaintext = decrypt(
        AeadAlgorithm::Aes256Gcm,
        &canary_key,
        &CANARY_NONCE,
        b"",
        &canary_ct,
    )
    .map_err(|_| VaultError::VmkCanaryMismatch)?;

    if plaintext != CANARY_PLAINTEXT {
        return Err(VaultError::VmkCanaryMismatch);
    }

    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn temp_db_path(name: &str) -> std::path::PathBuf {
        temp_dir().join(format!("aegis-vault-test-{name}-{}.db", std::process::id()))
    }

    #[test]
    fn create_new_then_open_existing_succeeds_with_correct_vmk() {
        let path = temp_db_path("create-open");
        let _ = std::fs::remove_file(&path);
        let vmk = [0x55u8; 32];

        create_new(&path, &vmk).unwrap();
        open_existing(&path, &vmk).unwrap();

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn open_existing_with_wrong_vmk_fails_canary() {
        let path = temp_db_path("wrong-vmk");
        let _ = std::fs::remove_file(&path);
        let right_vmk = [0x11u8; 32];
        let wrong_vmk = [0x22u8; 32];

        create_new(&path, &right_vmk).unwrap();
        let result = open_existing(&path, &wrong_vmk);
        assert!(matches!(result, Err(VaultError::VmkCanaryMismatch)));

        std::fs::remove_file(&path).unwrap();
    }
}
