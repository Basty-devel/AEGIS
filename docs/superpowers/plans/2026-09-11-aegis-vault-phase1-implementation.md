# aegis-vault Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `aegis-vault` Phase 1 — an encrypted local key/value store with hardware-backed (Windows Credential Manager / Linux Secret Service) key isolation, a strict zero-fallback policy, and GDPR Art. 17 (cryptographic erasure) / Art. 20 (signed, encrypted export) engines.

**Architecture:** A Vault Master Key (VMK) lives only in the OS credential store, never on disk. Every record gets its own random Data Encryption Key (DEK), wrapped under a VMK-derived key; the wrapped DEK — not the ciphertext — is what erasure destroys. SQLCipher encrypts the database file as a whole underneath this, keyed by a second VMK-derived key. Everything is a pure, synchronous API — no async, no network.

**Tech Stack:** Rust, `rusqlite` (bundled SQLCipher + vendored OpenSSL), `keyring` 4.2 (`v1` feature, the default), `aegis-crypto` 0.1.4 (AEAD, Argon2id, dual signatures), `hkdf`/`sha2` (this crate's own internal KDF — see Task 2 for why `aegis_crypto::kdf::derive_key` doesn't fit), `serde_json` + `base64` for the GDPR export format.

**Spec:** [`docs/superpowers/specs/2026-09-11-aegis-vault-phase1-design.md`](../specs/2026-09-11-aegis-vault-phase1-design.md) — executors should read both.

## Global Constraints

- Nothing in this crate may panic on data an attacker or a corrupted disk controls (malformed rows, keyring failures, SQLCipher errors) — always return `VaultError`. RNG failure may still panic (fail-closed), matching `aegis-crypto`'s existing convention.
- No `unwrap()`/`expect()` in non-test code (workspace lint: `unsafe_code = "deny"`; this project's global convention additionally forbids `unwrap`/`expect` outside tests).
- Every secret (VMK, derived keys, DEKs, plaintext) is `zeroize::Zeroizing` or a type that wipes on drop.
- Zero-fallback is structural: no code path in this crate may obtain or store a VMK other than through `HardwareKeyStore`. Never add a "plaintext fallback" branch, even behind a flag.
- Two-tier testing per the spec: default tests run against an in-crate `MockKeyStore` (no OS calls); a small `#[ignore]`-by-default set exercises the real OS credential store.
- Domain-separate every derived key with a distinct HKDF `info` label — never reuse VMK directly as an AEAD key for two different purposes.

---

### Task 1: Crate scaffolding and error type

**Files:**
- Modify: `crates/aegis-vault/Cargo.toml`
- Modify: `crates/aegis-vault/src/lib.rs`
- Create: `crates/aegis-vault/src/error.rs`

**Interfaces:**
- Produces: `pub enum VaultError` (`#[non_exhaustive]`), `impl From<aegis_crypto::CryptoError> for VaultError`, `impl std::error::Error for VaultError`, `impl std::fmt::Display for VaultError`.

- [ ] **Step 1: Write the failing test**

Create `crates/aegis-vault/src/error.rs`:

```rust
//! Errors returned by `aegis-vault`'s fallible operations.

use std::fmt;

/// Errors returned by `aegis-vault`. Non-exhaustive: new failure modes
/// may be added without a semver break.
#[derive(Debug)]
#[non_exhaustive]
pub enum VaultError {
    /// The hardware-backed credential store (Windows Credential
    /// Manager / Linux Secret Service) could not be reached or
    /// initialized. This is the zero-fallback trigger — there is no
    /// other code path that can obtain or store a VMK.
    HardwareKeyStoreUnavailable(String),
    /// A VMK was loaded but failed to decrypt the stored canary —
    /// either the wrong key or a corrupted store.
    VmkCanaryMismatch,
    /// A stored record's bytes are malformed in a way that cannot be
    /// the product of this crate's own writes.
    StorageCorrupted(String),
    /// Underlying `rusqlite`/SQLCipher failure.
    Sqlite(rusqlite::Error),
    /// Underlying filesystem failure.
    Io(std::io::Error),
    /// A primitive-level cryptographic failure from `aegis-crypto`.
    Crypto(aegis_crypto::CryptoError),
}

impl From<aegis_crypto::CryptoError> for VaultError {
    fn from(err: aegis_crypto::CryptoError) -> Self {
        VaultError::Crypto(err)
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(err: rusqlite::Error) -> Self {
        VaultError::Sqlite(err)
    }
}

impl From<std::io::Error> for VaultError {
    fn from(err: std::io::Error) -> Self {
        VaultError::Io(err)
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::HardwareKeyStoreUnavailable(detail) => {
                write!(f, "hardware-backed key store unavailable: {detail}")
            }
            VaultError::VmkCanaryMismatch => {
                write!(f, "vault master key failed canary verification")
            }
            VaultError::StorageCorrupted(detail) => {
                write!(f, "vault storage corrupted: {detail}")
            }
            VaultError::Sqlite(err) => write!(f, "sqlite/sqlcipher error: {err}"),
            VaultError::Io(err) => write!(f, "filesystem error: {err}"),
            VaultError::Crypto(err) => write!(f, "cryptographic error: {err}"),
        }
    }
}

impl std::error::Error for VaultError {}

#[cfg(test)]
mod tests {
    use super::VaultError;

    #[test]
    fn display_names_the_failure_kind() {
        let err = VaultError::VmkCanaryMismatch;
        assert_eq!(
            err.to_string(),
            "vault master key failed canary verification"
        );
    }

    #[test]
    fn hardware_key_store_unavailable_includes_detail() {
        let err = VaultError::HardwareKeyStoreUnavailable("no Secret Service daemon".into());
        assert!(err.to_string().contains("no Secret Service daemon"));
    }

    #[test]
    fn implements_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<VaultError>();
    }

    #[test]
    fn crypto_error_converts() {
        let crypto_err = aegis_crypto::CryptoError::InvalidPeerPublicKey;
        let vault_err: VaultError = crypto_err.into();
        assert!(matches!(vault_err, VaultError::Crypto(_)));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails to compile**

Run: `cargo test -p aegis-vault 2>&1 | head -40`
Expected: FAIL — `aegis-crypto` is not yet a dependency, `rusqlite` is not a dependency, and `lib.rs` doesn't declare `mod error;`.

- [ ] **Step 3: Add dependencies and wire up the module**

Replace `crates/aegis-vault/Cargo.toml`:

```toml
[package]
name = "aegis-vault"
version.workspace = true
edition.workspace = true

[lints]
workspace = true

[dependencies]
aegis-crypto = { path = "../aegis-crypto" }
rusqlite = { version = "0.40", features = ["bundled-sqlcipher-vendored-openssl"] }
keyring = "4.2"
hkdf = "0.13"
sha2 = "0.11"
zeroize = { version = "1.9", features = ["derive"] }
getrandom = "0.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.23"

[dev-dependencies]
hex = "0.4"
```

`bundled-sqlcipher-vendored-openssl` (not plain `bundled-sqlcipher`) specifically because it also compiles OpenSSL from source — SQLCipher's own crypto backend needs OpenSSL, and vendoring it too keeps the build reproducible without a system OpenSSL/libcrypto install on Windows/Linux/CI, matching the "bundled, no system dependency" decision from design.

Replace `crates/aegis-vault/src/lib.rs`:

```rust
//! SQLCipher-encrypted local storage, hardware key isolation with a
//! strict zero-fallback policy, and GDPR Art. 17/20 erasure and
//! export.
//!
//! See `AEGIS.Plan.V0.2.md` Section 4 and
//! `docs/superpowers/specs/2026-09-11-aegis-vault-phase1-design.md`.
//! Depends on `aegis-crypto` only.

pub mod error;
mod kdf;
mod keystore;
mod db;
mod vault;
mod export;

pub use error::VaultError;
pub use vault::{Vault, VaultConfig};
```

(The `mod kdf; mod keystore; mod db; mod vault; mod export;` lines will fail to compile until Tasks 2-6 create those files — for this task, temporarily comment out every `mod` line except `pub mod error;` and the corresponding `pub use` lines, so this task's own test can compile and pass in isolation. Restore them incrementally in later tasks.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p aegis-vault 2>&1 | tail -20`
Expected: PASS — 4 tests in `error::tests`.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-vault/Cargo.toml crates/aegis-vault/src/lib.rs crates/aegis-vault/src/error.rs
git commit -m "aegis-vault: scaffold crate, add VaultError"
```

---

### Task 2: Internal domain-separated KDF

**Files:**
- Create: `crates/aegis-vault/src/kdf.rs`
- Modify: `crates/aegis-vault/src/lib.rs` (uncomment `mod kdf;`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `pub(crate) fn derive_sqlcipher_key(vmk: &[u8; 32]) -> Zeroizing<[u8; 32]>`, `pub(crate) fn derive_dek_wrap_key(vmk: &[u8; 32]) -> Zeroizing<[u8; 32]>`, `pub(crate) fn derive_canary_key(vmk: &[u8; 32]) -> Zeroizing<[u8; 32]>` — used by Tasks 5, 6, 7.

**Why not `aegis_crypto::kdf::derive_key`:** that function's signature mandatorily binds two parties' public keys into its `info` (`pubkey_a`, `pubkey_b`) — it exists for handshake transcripts (X3DH), not single-secret internal derivation, and its own module doc says the binding "has no way to omit them." Forcing VMK-internal derivation through it would mean passing empty/dummy public keys into a function whose whole point is binding real ones. `aegis-ratchet`'s `kdf_chain.rs` set the precedent for this exact situation (it needed a non-`None` salt `derive_key` doesn't support) by wrapping `hkdf::Hkdf` directly instead; this crate does the same for a different reason.

- [ ] **Step 1: Write the failing test**

Create `crates/aegis-vault/src/kdf.rs`:

```rust
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

/// The key that wraps (encrypts) each record's per-record DEK.
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p aegis-vault kdf:: 2>&1 | head -20`
Expected: FAIL — `mod kdf;` isn't uncommented in `lib.rs` yet.

- [ ] **Step 3: Uncomment the module**

In `crates/aegis-vault/src/lib.rs`, uncomment `mod kdf;`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p aegis-vault kdf:: 2>&1 | tail -15`
Expected: PASS — 4 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-vault/src/kdf.rs crates/aegis-vault/src/lib.rs
git commit -m "aegis-vault: add internal domain-separated KDF"
```

---

### Task 3: HardwareKeyStore trait and in-crate mock

**Files:**
- Create: `crates/aegis-vault/src/keystore.rs`
- Modify: `crates/aegis-vault/src/lib.rs` (uncomment `mod keystore;`)

**Interfaces:**
- Produces: `pub(crate) trait HardwareKeyStore { fn store_vmk(&self, vmk: &[u8; 32]) -> Result<(), VaultError>; fn load_vmk(&self) -> Result<Zeroizing<[u8; 32]>, VaultError>; fn destroy_vmk(&self) -> Result<(), VaultError>; }`, and `#[cfg(test)] pub(crate) struct MockKeyStore` implementing it — used by every later test that needs a `Vault` (Tasks 6-9) instead of touching a real OS credential store.

- [ ] **Step 1: Write the failing test**

Create `crates/aegis-vault/src/keystore.rs`:

```rust
//! The hardware-backed key store abstraction. Phase 1 ships one real
//! implementation (`KeyringBackend`, Task 4) covering Windows
//! Credential Manager and Linux Secret Service/Keyutils. This trait
//! boundary exists so a future Android Keystore / Apple Secure
//! Enclave backend can be added without touching `Vault`'s logic.

use crate::error::VaultError;
use zeroize::Zeroizing;

/// Zero-fallback boundary: the only way anything in this crate can
/// obtain or store a Vault Master Key.
pub(crate) trait HardwareKeyStore {
    fn store_vmk(&self, vmk: &[u8; 32]) -> Result<(), VaultError>;
    fn load_vmk(&self) -> Result<Zeroizing<[u8; 32]>, VaultError>;
    fn destroy_vmk(&self) -> Result<(), VaultError>;
}

#[cfg(test)]
pub(crate) struct MockKeyStore {
    stored: std::sync::Mutex<Option<[u8; 32]>>,
    unavailable: bool,
}

#[cfg(test)]
impl MockKeyStore {
    pub(crate) fn new() -> Self {
        Self {
            stored: std::sync::Mutex::new(None),
            unavailable: false,
        }
    }

    /// A mock that simulates the OS credential store being
    /// unreachable — every operation returns
    /// `HardwareKeyStoreUnavailable`, exercising the zero-fallback
    /// path without needing a real broken OS store.
    pub(crate) fn unavailable() -> Self {
        Self {
            stored: std::sync::Mutex::new(None),
            unavailable: true,
        }
    }
}

#[cfg(test)]
impl HardwareKeyStore for MockKeyStore {
    fn store_vmk(&self, vmk: &[u8; 32]) -> Result<(), VaultError> {
        if self.unavailable {
            return Err(VaultError::HardwareKeyStoreUnavailable(
                "mock: simulated unavailable store".into(),
            ));
        }
        *self.stored.lock().unwrap() = Some(*vmk);
        Ok(())
    }

    fn load_vmk(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        if self.unavailable {
            return Err(VaultError::HardwareKeyStoreUnavailable(
                "mock: simulated unavailable store".into(),
            ));
        }
        self.stored
            .lock()
            .unwrap()
            .map(Zeroizing::new)
            .ok_or_else(|| VaultError::StorageCorrupted("mock: no VMK stored".into()))
    }

    fn destroy_vmk(&self) -> Result<(), VaultError> {
        if self.unavailable {
            return Err(VaultError::HardwareKeyStoreUnavailable(
                "mock: simulated unavailable store".into(),
            ));
        }
        *self.stored.lock().unwrap() = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_stored_vmk() {
        let store = MockKeyStore::new();
        let vmk = [0x77u8; 32];
        store.store_vmk(&vmk).unwrap();
        assert_eq!(*store.load_vmk().unwrap(), vmk);
    }

    #[test]
    fn destroy_makes_load_fail() {
        let store = MockKeyStore::new();
        store.store_vmk(&[0x11u8; 32]).unwrap();
        store.destroy_vmk().unwrap();
        assert!(store.load_vmk().is_err());
    }

    #[test]
    fn unavailable_store_fails_every_operation() {
        let store = MockKeyStore::unavailable();
        assert!(matches!(
            store.store_vmk(&[0u8; 32]),
            Err(VaultError::HardwareKeyStoreUnavailable(_))
        ));
        assert!(matches!(
            store.load_vmk(),
            Err(VaultError::HardwareKeyStoreUnavailable(_))
        ));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p aegis-vault keystore:: 2>&1 | head -20`
Expected: FAIL — `mod keystore;` not yet uncommented.

- [ ] **Step 3: Uncomment the module**

In `crates/aegis-vault/src/lib.rs`, uncomment `mod keystore;`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p aegis-vault keystore:: 2>&1 | tail -15`
Expected: PASS — 3 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-vault/src/keystore.rs crates/aegis-vault/src/lib.rs
git commit -m "aegis-vault: add HardwareKeyStore trait and in-crate mock"
```

---

### Task 4: KeyringBackend (real OS credential store)

**Files:**
- Modify: `crates/aegis-vault/src/keystore.rs`

**Interfaces:**
- Consumes: `HardwareKeyStore` trait (Task 3).
- Produces: `pub(crate) struct KeyringBackend { service_name: String }` with `pub(crate) fn new(service_name: impl Into<String>) -> Self`, implementing `HardwareKeyStore` — used by `Vault::open` (Task 6).

- [ ] **Step 1: Write the failing test**

Append to `crates/aegis-vault/src/keystore.rs`, above the existing `#[cfg(test)] mod tests` block:

```rust
/// The real, OS-native `HardwareKeyStore`. `keyring`'s `v1` feature
/// (the crate's default) automatically selects Windows Credential
/// Manager on Windows and the Secret Service (via `zbus`) on *nix —
/// one implementation covers both platforms in Phase 1's scope.
pub(crate) struct KeyringBackend {
    service_name: String,
}

impl KeyringBackend {
    pub(crate) fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(&self.service_name, "vmk").map_err(map_keyring_error)
    }
}

impl HardwareKeyStore for KeyringBackend {
    fn store_vmk(&self, vmk: &[u8; 32]) -> Result<(), VaultError> {
        self.entry()?.set_secret(vmk).map_err(map_keyring_error)
    }

    fn load_vmk(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let secret = self.entry()?.get_secret().map_err(map_keyring_error)?;
        let array: [u8; 32] = secret.as_slice().try_into().map_err(|_| {
            VaultError::StorageCorrupted(format!(
                "keyring VMK entry has wrong length: {} bytes, expected 32",
                secret.len()
            ))
        })?;
        Ok(Zeroizing::new(array))
    }

    fn destroy_vmk(&self) -> Result<(), VaultError> {
        self.entry()?.delete_credential().map_err(map_keyring_error)
    }
}

/// `keyring::Error` is `#[non_exhaustive]`; `NoDefaultStore` and
/// `NoStorageAccess` mean the platform credential store itself
/// couldn't be reached — the zero-fallback trigger. Everything else
/// is a store-level failure this crate can't recover from either, so
/// it's folded into the same variant with its detail preserved.
fn map_keyring_error(err: keyring::Error) -> VaultError {
    match err {
        keyring::Error::NoDefaultStore | keyring::Error::NoStorageAccess(_) => {
            VaultError::HardwareKeyStoreUnavailable(err.to_string())
        }
        other => VaultError::HardwareKeyStoreUnavailable(other.to_string()),
    }
}
```

Add to the top of `crates/aegis-vault/src/keystore.rs` (after the existing `use` lines):

```rust
use keyring;
```

(This `use` line is only needed if `keyring` isn't already in scope via the 2021-edition prelude path resolution — `keyring::Entry` used with its full path in the code above works without it either way; omit if `cargo build` doesn't complain.)

Add real-backend integration tests at the bottom of the file, inside a **new**, separate `#[cfg(test)] mod real_backend_tests` block (kept apart from the mock-based `tests` module so `#[ignore]` reads as "this whole module is opt-in", not scattered per-test):

```rust
#[cfg(test)]
mod real_backend_tests {
    use super::*;

    /// Exercises the actual OS credential store. `#[ignore]` by
    /// default — a fresh CI container often has no Secret Service
    /// daemon running. Run explicitly: `cargo test -p aegis-vault
    /// real_backend_tests -- --ignored`.
    #[test]
    #[ignore]
    fn round_trips_through_the_real_os_store() {
        let backend = KeyringBackend::new("aegis-vault-test-real-backend");
        let vmk = [0x99u8; 32];
        backend.store_vmk(&vmk).unwrap();
        assert_eq!(*backend.load_vmk().unwrap(), vmk);
        backend.destroy_vmk().unwrap();
        assert!(backend.load_vmk().is_err());
    }
}
```

- [ ] **Step 2: Run the mock-backed tests to confirm nothing broke**

Run: `cargo test -p aegis-vault keystore:: 2>&1 | tail -15`
Expected: PASS — the 3 existing mock tests still pass (this step adds code, doesn't change them).

- [ ] **Step 3: Run the real-backend test manually to verify it actually passes on this machine**

Run: `cargo test -p aegis-vault real_backend_tests -- --ignored 2>&1 | tail -20`
Expected: PASS on this Windows dev machine (Windows Credential Manager is always available here). This is a one-time manual sanity check, not part of the default suite.

- [ ] **Step 4: Commit**

```bash
git add crates/aegis-vault/src/keystore.rs
git commit -m "aegis-vault: add KeyringBackend (real OS credential store)"
```

---

### Task 5: SQLCipher schema, connection bootstrap, canary

**Files:**
- Create: `crates/aegis-vault/src/db.rs`
- Modify: `crates/aegis-vault/src/lib.rs` (uncomment `mod db;`)

**Interfaces:**
- Consumes: `kdf::derive_sqlcipher_key`, `kdf::derive_canary_key` (Task 2).
- Produces: `pub(crate) fn create_new(db_path: &Path, vmk: &[u8; 32]) -> Result<rusqlite::Connection, VaultError>`, `pub(crate) fn open_existing(db_path: &Path, vmk: &[u8; 32]) -> Result<rusqlite::Connection, VaultError>` — used by `Vault::open` (Task 6). Both leave the returned `Connection` with the `vault_meta`/`vault_records` schema present and the canary verified.

- [ ] **Step 1: Write the failing test**

Create `crates/aegis-vault/src/db.rs`:

```rust
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

const CANARY_PLAINTEXT: &[u8] = b"AEGIS-VAULT-CANARY-v1";
const CANARY_NONCE: [u8; 12] = [0u8; 12]; // fixed: one canary row, one key, written exactly once per vault.

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

fn set_sqlcipher_key(conn: &Connection, vmk: &[u8; 32]) -> Result<(), VaultError> {
    let sqlcipher_key = derive_sqlcipher_key(vmk);
    conn.pragma_update(None, "key", sqlcipher_key.as_slice())?;
    Ok(())
}

/// Bootstrap a brand-new vault: open (creating) the file, key it,
/// create the schema, and write the canary.
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p aegis-vault db:: 2>&1 | head -30`
Expected: FAIL — `mod db;` not yet uncommented; also confirms whether `open_existing` with a wrong VMK genuinely fails via SQLCipher's own key rejection before the canary check even runs (SQLCipher typically returns `DatabaseError`/"file is not a database" from the `query_row` call itself when the page-cipher key is wrong, which the `.map_err(|_| VaultError::VmkCanaryMismatch)` on the `query_row` call already normalizes to the same error the explicit canary check would produce — this is expected and fine, not a bug: both paths converge on the same `VmkCanaryMismatch` regardless of which layer detects the wrong key first).

- [ ] **Step 3: Uncomment the module**

In `crates/aegis-vault/src/lib.rs`, uncomment `mod db;`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p aegis-vault db:: 2>&1 | tail -20`
Expected: PASS — 2 tests. (First run of this task will be slow — `bundled-sqlcipher-vendored-openssl` compiles SQLCipher and OpenSSL from source.)

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-vault/src/db.rs crates/aegis-vault/src/lib.rs
git commit -m "aegis-vault: add SQLCipher bootstrap, schema, and VMK canary"
```

---

### Task 6: `Vault::open`

**Files:**
- Create: `crates/aegis-vault/src/vault.rs`
- Modify: `crates/aegis-vault/src/lib.rs` (uncomment `mod vault;`, `pub use vault::{Vault, VaultConfig};`)

**Interfaces:**
- Consumes: `keystore::{HardwareKeyStore, KeyringBackend, MockKeyStore}` (Tasks 3-4), `db::{create_new, open_existing}` (Task 5).
- Produces: `pub struct VaultConfig { pub db_path: PathBuf, pub keyring_service_name: String }`, `pub struct Vault { conn: rusqlite::Connection, vmk: Zeroizing<[u8; 32]>, db_path: PathBuf, keyring_service_name: String }`, `impl Vault { pub fn open(config: VaultConfig) -> Result<Self, VaultError> }` plus a `pub(crate) fn open_with_store(db_path: &Path, store: &dyn HardwareKeyStore, keyring_service_name: String) -> Result<Self, VaultError>` test seam — used directly by every later task's tests instead of going through the real `KeyringBackend`. `db_path`/`keyring_service_name` are retained on `Vault` (not just consumed and dropped) specifically because Task 9's `destroy_vault` needs both later — decided now so no later task has to retrofit fields onto an already-written struct.

- [ ] **Step 1: Write the failing test**

Create `crates/aegis-vault/src/vault.rs`:

```rust
//! The `Vault` public API: a generic, namespaced, encrypted key/value
//! store over SQLCipher with hardware-backed key isolation. See
//! design spec Sections 1-3.

use crate::db;
use crate::error::VaultError;
use crate::keystore::{HardwareKeyStore, KeyringBackend};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct VaultConfig {
    pub db_path: PathBuf,
    pub keyring_service_name: String,
}

pub struct Vault {
    pub(crate) conn: Connection,
    pub(crate) vmk: Zeroizing<[u8; 32]>,
    db_path: PathBuf,
    keyring_service_name: String,
}

impl Vault {
    /// Opens an existing vault at `config.db_path`, or creates one if
    /// no file exists there yet. Both paths go through
    /// `HardwareKeyStore` — if the OS credential store can't be
    /// reached, this returns `Err` and no vault is created or opened.
    pub fn open(config: VaultConfig) -> Result<Self, VaultError> {
        let store = KeyringBackend::new(config.keyring_service_name.clone());
        Self::open_with_store(&config.db_path, &store, config.keyring_service_name)
    }

    /// Test seam: identical to `open` but takes any `HardwareKeyStore`,
    /// so tests can pass `MockKeyStore` instead of talking to a real
    /// OS credential store. `keyring_service_name` is only ever read
    /// again by `destroy_vault` (Task 9) reconstructing a real
    /// `KeyringBackend` — `MockKeyStore`-based tests can pass any
    /// fixed string.
    pub(crate) fn open_with_store(
        db_path: &Path,
        store: &dyn HardwareKeyStore,
        keyring_service_name: String,
    ) -> Result<Self, VaultError> {
        let db_exists = db_path.exists();

        let vmk = if db_exists {
            store.load_vmk()?
        } else {
            let mut vmk = Zeroizing::new([0u8; 32]);
            getrandom::fill(vmk.as_mut()).map_err(|_| {
                VaultError::StorageCorrupted("OS RNG failure generating VMK".into())
            })?;
            store.store_vmk(&vmk)?;
            vmk
        };

        let conn = if db_exists {
            db::open_existing(db_path, &vmk)?
        } else {
            db::create_new(db_path, &vmk)?
        };

        Ok(Vault {
            conn,
            vmk,
            db_path: db_path.to_path_buf(),
            keyring_service_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MockKeyStore;
    use std::env::temp_dir;

    fn temp_db_path(name: &str) -> PathBuf {
        temp_dir().join(format!("aegis-vault-test-{name}-{}.db", std::process::id()))
    }

    #[test]
    fn open_creates_a_new_vault_when_no_file_exists() {
        let path = temp_db_path("open-create");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();

        let vault =
            Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        assert_eq!(vault.vmk.len(), 32);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn open_reopens_an_existing_vault_with_the_same_vmk() {
        let path = temp_db_path("open-reopen");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();

        let first =
            Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        let first_vmk = *first.vmk;
        drop(first);

        let second =
            Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        assert_eq!(*second.vmk, first_vmk);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn open_fails_when_hardware_store_is_unavailable() {
        let path = temp_db_path("open-unavailable");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::unavailable();

        let result =
            Vault::open_with_store(&path, &store, "aegis-vault-test".to_string());
        assert!(matches!(
            result,
            Err(VaultError::HardwareKeyStoreUnavailable(_))
        ));
        assert!(!path.exists(), "no database file should be left behind");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p aegis-vault vault:: 2>&1 | head -20`
Expected: FAIL — `mod vault;` not yet uncommented.

- [ ] **Step 3: Uncomment the module and export**

In `crates/aegis-vault/src/lib.rs`, uncomment `mod vault;` and `pub use vault::{Vault, VaultConfig};`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p aegis-vault vault:: 2>&1 | tail -20`
Expected: PASS — 3 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-vault/src/vault.rs crates/aegis-vault/src/lib.rs
git commit -m "aegis-vault: add Vault::open (VMK load/create + DB bootstrap)"
```

---

### Task 7: `Vault::put` / `Vault::get` — per-record envelope encryption

**Files:**
- Modify: `crates/aegis-vault/src/vault.rs`

**Interfaces:**
- Consumes: `kdf::derive_dek_wrap_key` (Task 2), `Vault { conn, vmk }` (Task 6).
- Produces: `impl Vault { pub fn put(&mut self, namespace: &str, key: &str, plaintext: &[u8]) -> Result<(), VaultError>; pub fn get(&self, namespace: &str, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError>; }` — used by Task 8 (`erase`, `list_keys`) and Task 10 (`export`).

- [ ] **Step 1: Write the failing test**

Add to `crates/aegis-vault/src/vault.rs`'s `tests` module:

```rust
    #[test]
    fn put_then_get_round_trips_plaintext() {
        let path = temp_db_path("put-get");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.put("messages", "msg-1", b"hello aegis").unwrap();
        let got = vault.get("messages", "msg-1").unwrap().unwrap();
        assert_eq!(&*got, b"hello aegis");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn get_of_missing_key_returns_none_not_error() {
        let path = temp_db_path("get-missing");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        assert!(vault.get("messages", "nope").unwrap().is_none());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn put_overwrites_an_existing_record_with_a_fresh_dek() {
        let path = temp_db_path("put-overwrite");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.put("contacts", "alice", b"v1").unwrap();
        vault.put("contacts", "alice", b"v2").unwrap();
        let got = vault.get("contacts", "alice").unwrap().unwrap();
        assert_eq!(&*got, b"v2");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn different_namespaces_do_not_collide() {
        let path = temp_db_path("namespaces");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.put("ns-a", "key", b"a-value").unwrap();
        vault.put("ns-b", "key", b"b-value").unwrap();
        assert_eq!(&*vault.get("ns-a", "key").unwrap().unwrap(), b"a-value");
        assert_eq!(&*vault.get("ns-b", "key").unwrap().unwrap(), b"b-value");

        std::fs::remove_file(&path).unwrap();
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aegis-vault vault:: 2>&1 | head -30`
Expected: FAIL — `put`/`get` don't exist yet.

- [ ] **Step 3: Implement `put` and `get`**

Add to `crates/aegis-vault/src/vault.rs`, inside `impl Vault` (after `open`), and add the needed imports at the top of the file:

```rust
use crate::kdf::derive_dek_wrap_key;
use aegis_crypto::aead::{decrypt, encrypt, AeadAlgorithm};
```

```rust
    /// Encrypts `plaintext` under a fresh, random per-record DEK,
    /// wraps that DEK under a VMK-derived key, and upserts the
    /// `(namespace, key)` row. See design spec Section 1 for why the
    /// DEK is random and stored (not derived) — that's what makes
    /// `erase` (Task 8) a real cryptographic-shredding guarantee.
    pub fn put(&mut self, namespace: &str, key: &str, plaintext: &[u8]) -> Result<(), VaultError> {
        let mut dek = Zeroizing::new([0u8; 32]);
        getrandom::fill(dek.as_mut())
            .map_err(|_| VaultError::StorageCorrupted("OS RNG failure generating DEK".into()))?;

        let mut record_nonce = [0u8; 12];
        getrandom::fill(&mut record_nonce)
            .map_err(|_| VaultError::StorageCorrupted("OS RNG failure generating nonce".into()))?;
        let ciphertext = encrypt(
            AeadAlgorithm::Aes256Gcm,
            &dek,
            &record_nonce,
            b"",
            plaintext,
        )
        .map_err(|_| VaultError::StorageCorrupted("failed to seal record".into()))?;

        let mut dek_nonce = [0u8; 12];
        getrandom::fill(&mut dek_nonce)
            .map_err(|_| VaultError::StorageCorrupted("OS RNG failure generating DEK nonce".into()))?;
        let wrap_key = derive_dek_wrap_key(&self.vmk);
        let wrapped_dek = encrypt(
            AeadAlgorithm::Aes256Gcm,
            &wrap_key,
            &dek_nonce,
            b"",
            dek.as_slice(),
        )
        .map_err(|_| VaultError::StorageCorrupted("failed to wrap DEK".into()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        self.conn.execute(
            "INSERT INTO vault_records (namespace, key, wrapped_dek, dek_nonce, ciphertext, nonce, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
             ON CONFLICT (namespace, key) DO UPDATE SET
                wrapped_dek = excluded.wrapped_dek,
                dek_nonce   = excluded.dek_nonce,
                ciphertext  = excluded.ciphertext,
                nonce       = excluded.nonce,
                updated_at  = excluded.updated_at",
            rusqlite::params![
                namespace,
                key,
                wrapped_dek,
                dek_nonce.to_vec(),
                ciphertext,
                record_nonce.to_vec(),
                now,
            ],
        )?;

        Ok(())
    }

    /// Returns `Ok(None)` if `(namespace, key)` has no record, or has
    /// been `erase`d (Task 8) — from the caller's perspective those
    /// two cases are indistinguishable, which is the point.
    pub fn get(&self, namespace: &str, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT wrapped_dek, dek_nonce, ciphertext, nonce FROM vault_records
                 WHERE namespace = ?1 AND key = ?2",
                rusqlite::params![namespace, key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .ok();

        let Some((Some(wrapped_dek), Some(dek_nonce), ciphertext, nonce)) = row else {
            return Ok(None);
        };

        let dek_nonce_arr: [u8; 12] = dek_nonce
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::StorageCorrupted("dek_nonce has wrong length".into()))?;
        let wrap_key = derive_dek_wrap_key(&self.vmk);
        let dek_bytes = decrypt(
            AeadAlgorithm::Aes256Gcm,
            &wrap_key,
            &dek_nonce_arr,
            b"",
            &wrapped_dek,
        )
        .map_err(|_| VaultError::StorageCorrupted("failed to unwrap DEK".into()))?;
        let dek: [u8; 32] = dek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::StorageCorrupted("unwrapped DEK has wrong length".into()))?;

        let nonce_arr: [u8; 12] = nonce
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::StorageCorrupted("nonce has wrong length".into()))?;
        let plaintext = decrypt(AeadAlgorithm::Aes256Gcm, &dek, &nonce_arr, b"", &ciphertext)
            .map_err(|_| VaultError::StorageCorrupted("failed to open record".into()))?;

        Ok(Some(Zeroizing::new(plaintext)))
    }
```

Note the `let Some((Some(wrapped_dek), Some(dek_nonce), ciphertext, nonce)) = row else { return Ok(None); }` pattern: `wrapped_dek`/`dek_nonce` are nullable columns specifically so `erase` (Task 8) can `UPDATE ... SET wrapped_dek = NULL, dek_nonce = NULL` without deleting the row — `get` treats a NULL-wrapped-DEK row exactly like a missing row.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p aegis-vault vault:: 2>&1 | tail -25`
Expected: PASS — 7 tests total (3 from Task 6, 4 new).

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-vault/src/vault.rs
git commit -m "aegis-vault: add put/get with per-record envelope encryption"
```

---

### Task 8: `Vault::list_keys` / `Vault::erase` — Art. 17 per-record shredding

**Files:**
- Modify: `crates/aegis-vault/src/vault.rs`

**Interfaces:**
- Consumes: `Vault::put`/`get` (Task 7).
- Produces: `impl Vault { pub fn list_keys(&self, namespace: &str) -> Result<Vec<String>, VaultError>; pub fn erase(&mut self, namespace: &str, key: &str) -> Result<(), VaultError>; }`.

- [ ] **Step 1: Write the failing test**

Add to `crates/aegis-vault/src/vault.rs`'s `tests` module:

```rust
    #[test]
    fn list_keys_returns_all_keys_in_a_namespace() {
        let path = temp_db_path("list-keys");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.put("contacts", "alice", b"a").unwrap();
        vault.put("contacts", "bob", b"b").unwrap();
        vault.put("messages", "msg-1", b"m").unwrap();

        let mut keys = vault.list_keys("contacts").unwrap();
        keys.sort();
        assert_eq!(keys, vec!["alice".to_string(), "bob".to_string()]);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn erase_makes_get_return_none() {
        let path = temp_db_path("erase-get-none");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.put("messages", "secret", b"gone soon").unwrap();
        vault.erase("messages", "secret").unwrap();

        assert!(vault.get("messages", "secret").unwrap().is_none());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn erase_excludes_the_key_from_list_keys() {
        let path = temp_db_path("erase-list");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.put("contacts", "alice", b"a").unwrap();
        vault.erase("contacts", "alice").unwrap();

        assert!(vault.list_keys("contacts").unwrap().is_empty());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn erase_destroys_the_dek_but_leaves_ciphertext_bytes_on_disk() {
        // Proves erasure is real cryptographic shredding, not a
        // database DELETE: the ciphertext survives untouched while
        // the wrapped DEK needed to open it is gone.
        let path = temp_db_path("erase-shred-proof");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.put("messages", "secret", b"shred me").unwrap();
        let ciphertext_before: Vec<u8> = vault
            .conn
            .query_row(
                "SELECT ciphertext FROM vault_records WHERE namespace = 'messages' AND key = 'secret'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        vault.erase("messages", "secret").unwrap();

        let row: (Vec<u8>, Option<Vec<u8>>) = vault
            .conn
            .query_row(
                "SELECT ciphertext, wrapped_dek FROM vault_records WHERE namespace = 'messages' AND key = 'secret'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(row.0, ciphertext_before, "ciphertext bytes must survive erase");
        assert!(row.1.is_none(), "wrapped_dek must be gone after erase");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn erase_of_a_missing_key_is_an_idempotent_no_op() {
        let path = temp_db_path("erase-missing");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let mut vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();

        vault.erase("messages", "never-existed").unwrap();
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aegis-vault vault:: 2>&1 | head -30`
Expected: FAIL — `list_keys`/`erase` don't exist yet.

- [ ] **Step 3: Implement `list_keys` and `erase`**

Add to `crates/aegis-vault/src/vault.rs`, inside `impl Vault` (after `get`):

```rust
    /// Lists every key currently readable in `namespace` — a key
    /// whose DEK has been `erase`d is excluded, same as it is from
    /// `get`.
    pub fn list_keys(&self, namespace: &str) -> Result<Vec<String>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT key FROM vault_records WHERE namespace = ?1 AND wrapped_dek IS NOT NULL",
        )?;
        let keys = stmt
            .query_map([namespace], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keys)
    }

    /// Art. 17 per-record cryptographic shredding: destroys this
    /// record's wrapped DEK (zeroizing the in-memory copy before the
    /// `UPDATE`), leaving the ciphertext bytes in place but
    /// permanently unrecoverable — see design spec Section 4. A
    /// no-op if the key was already erased or never existed.
    pub fn erase(&mut self, namespace: &str, key: &str) -> Result<(), VaultError> {
        self.conn.execute(
            "UPDATE vault_records SET wrapped_dek = NULL, dek_nonce = NULL
             WHERE namespace = ?1 AND key = ?2",
            rusqlite::params![namespace, key],
        )?;
        Ok(())
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p aegis-vault vault:: 2>&1 | tail -30`
Expected: PASS — 12 tests total.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-vault/src/vault.rs
git commit -m "aegis-vault: add list_keys and per-record Art. 17 erasure"
```

---

### Task 9: `Vault::destroy_vault` — Art. 17 whole-vault purge

**Files:**
- Modify: `crates/aegis-vault/src/vault.rs`

**Interfaces:**
- Consumes: `HardwareKeyStore::destroy_vmk` (Task 3), `Vault` (Task 6).
- Produces: `impl Vault { pub fn destroy_vault(self) -> Result<(), VaultError> }` (consumes `self`) plus the same `open_with_store`-style test seam via a `pub(crate) fn destroy_vault_with_store(self, store: &dyn HardwareKeyStore) -> Result<(), VaultError>`.

- [ ] **Step 1: Write the failing test**

Add to `crates/aegis-vault/src/vault.rs`'s `tests` module:

```rust
    #[test]
    fn destroy_vault_makes_the_db_file_and_vmk_both_gone() {
        let path = temp_db_path("destroy");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        assert!(path.exists());

        vault.destroy_vault_with_store(&store).unwrap();

        assert!(!path.exists(), "database file should be deleted");
        assert!(store.load_vmk().is_err(), "VMK should be destroyed");
    }

    #[test]
    fn reopening_after_destroy_creates_a_brand_new_vault() {
        let path = temp_db_path("destroy-reopen");
        let _ = std::fs::remove_file(&path);
        let store = MockKeyStore::new();
        let vault = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        let old_vmk = *vault.vmk;
        vault.destroy_vault_with_store(&store).unwrap();

        let fresh = Vault::open_with_store(&path, &store, "aegis-vault-test".to_string()).unwrap();
        assert_ne!(*fresh.vmk, old_vmk, "a fresh vault gets a fresh VMK");

        std::fs::remove_file(&path).unwrap();
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aegis-vault vault:: 2>&1 | head -20`
Expected: FAIL — `destroy_vault_with_store` doesn't exist yet.

- [ ] **Step 3: Implement `destroy_vault`**

`Vault` already carries `db_path` and `keyring_service_name` (Task 6), so this task is additive only — no struct changes. Add to `crates/aegis-vault/src/vault.rs`, inside `impl Vault` (after `erase`):

```rust
    /// Art. 17 whole-vault purge ("local purge" in the plan text).
    /// Destroys VMK via the hardware store and deletes the database
    /// file. Because every derived key (SQLCipher's own page-cipher
    /// key included, Task 2) comes from VMK, destroying VMK alone
    /// already makes the file's contents permanently unrecoverable —
    /// deleting the file itself is a best-effort second step, not
    /// where the erasure guarantee lives.
    pub fn destroy_vault(self) -> Result<(), VaultError> {
        let store = KeyringBackend::new(self.keyring_service_name.clone());
        self.destroy_vault_with_store(&store)
    }

    /// Test seam, same pattern as `open_with_store`.
    pub(crate) fn destroy_vault_with_store(
        self,
        store: &dyn HardwareKeyStore,
    ) -> Result<(), VaultError> {
        store.destroy_vmk()?;
        drop(self.conn);
        if self.db_path.exists() {
            std::fs::remove_file(&self.db_path)?;
        }
        Ok(())
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p aegis-vault vault:: 2>&1 | tail -30`
Expected: PASS — 14 tests total. Also run `cargo test -p aegis-vault 2>&1 | tail -10` to confirm the whole crate (all modules) still passes after the `Vault` struct's field changes.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-vault/src/vault.rs
git commit -m "aegis-vault: add destroy_vault (Art. 17 whole-vault purge)"
```

---

### Task 10: GDPR Art. 20 export

**Files:**
- Create: `crates/aegis-vault/src/export.rs`
- Modify: `crates/aegis-vault/src/lib.rs` (uncomment `mod export;`)
- Modify: `crates/aegis-vault/src/vault.rs` (add `pub fn export`, delegating to `export.rs`)

**Interfaces:**
- Consumes: `Vault::list_keys`, `Vault::get` (Tasks 7-8), `aegis_crypto::signature::{DualKeyPair, DualSignature, verify_dual}`, `aegis_crypto::passphrase::derive_master_key_production`, `aegis_crypto::aead::{encrypt, decrypt, AeadAlgorithm}`.
- Produces: `pub(crate) fn export_vault(vault: &Vault, namespaces: &[&str], signing_key: &aegis_crypto::signature::DualKeyPair, passphrase: &str) -> Result<Vec<u8>, VaultError>` and `pub(crate) fn decrypt_and_verify_export(export_bytes: &[u8], passphrase: &str) -> Result<(serde_json::Value, bool), VaultError>` (the `bool` is signature validity — used by this task's own round-trip test to independently verify what `export_vault` produced, matching design spec Section 4/6's testing strategy).

- [ ] **Step 1: Write the failing test**

Create `crates/aegis-vault/src/export.rs`:

```rust
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
    let signed_json = serde_json::to_vec(&signed)
        .map_err(|e| VaultError::StorageCorrupted(format!("export serialization failed: {e}")))?;

    let mut salt = [0u8; ARGON2_SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|_| VaultError::StorageCorrupted("OS RNG failure generating export salt".into()))?;
    let mut export_key = [0u8; 32];
    derive_master_key_production(passphrase.as_bytes(), &salt, b"", b"", &mut export_key)
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

    let mut export_key = [0u8; 32];
    derive_master_key_production(passphrase.as_bytes(), salt, b"", b"", &mut export_key)
        .map_err(|e| VaultError::StorageCorrupted(format!("Argon2id failed: {e}")))?;

    let signed_json = decrypt(AeadAlgorithm::Aes256Gcm, &export_key, &nonce, b"", ciphertext)
        .map_err(|_| VaultError::StorageCorrupted("wrong passphrase or tampered export".into()))?;

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

        std::fs::remove_file(&path).unwrap();
    }
}
```

This test calls `Vault::open_with_store(&path, &store, "aegis-vault-test".to_string())` with the same three-argument signature established in Task 6.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aegis-vault export:: 2>&1 | head -30`
Expected: FAIL — `mod export;` not yet uncommented; `serde`/`base64` traits not yet derived/imported anywhere else in the crate.

- [ ] **Step 3: Wire up the module and the public `Vault::export` method**

In `crates/aegis-vault/src/lib.rs`, uncomment `mod export;`.

Add to `crates/aegis-vault/src/vault.rs`, inside `impl Vault` (after `destroy_vault`/`destroy_vault_with_store`):

```rust
    /// GDPR Art. 20 export. `namespaces` selects which keyspaces to
    /// include — most callers will want every namespace they know
    /// about; this crate has no way to enumerate namespaces itself
    /// since it doesn't track them as a first-class concept (design
    /// spec Section 0).
    pub fn export(
        &self,
        namespaces: &[&str],
        signing_key: &aegis_crypto::signature::DualKeyPair,
        passphrase: &str,
    ) -> Result<Vec<u8>, VaultError> {
        crate::export::export_vault(self, namespaces, signing_key, passphrase)
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p aegis-vault export:: 2>&1 | tail -20`
Expected: PASS — 2 tests.

Then run the whole crate: `cargo test -p aegis-vault 2>&1 | tail -15`
Expected: PASS — all tests across every module (roughly 27-29 total, real-backend test still `#[ignore]`d).

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-vault/src/export.rs crates/aegis-vault/src/lib.rs crates/aegis-vault/src/vault.rs
git commit -m "aegis-vault: add GDPR Art. 20 signed, encrypted export"
```

---

### Task 11: Crate documentation and final verification

**Files:**
- Create: `crates/aegis-vault/README.md`
- Create: `crates/aegis-vault/LICENSE` (copy verbatim from `crates/aegis-crypto/LICENSE` — same PolyForm Noncommercial 1.0.0 text)
- Modify: `crates/aegis-vault/Cargo.toml` (add `description`, `license`, `readme`, `repository.workspace = true`)
- Modify: `crates/aegis-vault/src/lib.rs` (expand the top-of-file doc comment to match the finished crate, replacing the "scaffolding only" note)

**Interfaces:** none — documentation and final checks only.

- [ ] **Step 1: Update `Cargo.toml` metadata**

Add to `crates/aegis-vault/Cargo.toml`'s `[package]` section (mirroring `aegis-crypto`/`aegis-ratchet`'s convention):

```toml
description = "SQLCipher-encrypted local storage with hardware-backed (Windows Credential Manager / Linux Secret Service) key isolation and GDPR Art. 17/20 compliance engines for the AegisPQC messenger. NOT independently audited."
license = "PolyForm-Noncommercial-1.0.0"
readme = "README.md"
repository.workspace = true
```

- [ ] **Step 2: Write `crates/aegis-vault/README.md`**

```markdown
# aegis-vault

SQLCipher-encrypted local storage with hardware-backed key isolation
for [AegisPQC](https://github.com/Basty-devel/AEGIS), a post-quantum
secure messenger. Phase 1 of `AEGIS.Plan.V0.2.md` Section 4: a
generic, namespaced encrypted key/value store, not concrete
message/contact schemas — see this crate's design spec for why.

> **NOT independently audited.** Do not rely on this code for
> life-critical communications until a third-party cryptographic audit
> has been completed.

## What this is

- **Hardware-backed key isolation, zero-fallback** ([`keystore`]) — a
  random Vault Master Key (VMK) lives only in the OS credential store
  (Windows Credential Manager / Linux Secret Service, via the
  `keyring` crate's `v1` API) and is never written to disk by this
  crate. If the OS store can't be reached, `Vault::open` fails outright
  — there is no lower-security fallback path anywhere in this crate.
- **Per-record envelope encryption** ([`vault`]) — every record gets
  its own random Data Encryption Key (DEK), encrypted with
  `aegis_crypto::aead` (AES-256-GCM) and wrapped under a VMK-derived
  key. SQLCipher's own page cipher (AES-256-CBC + HMAC-SHA512 — not
  GCM, despite what the plan document's storage bullet says) encrypts
  the database file underneath this as a second, whole-file layer.
- **GDPR Art. 17 erasure** — `Vault::erase` destroys one record's
  wrapped DEK, making that record's ciphertext permanently
  unrecoverable even though its bytes may still exist in the database
  file until VACUUM. `Vault::destroy_vault` destroys VMK itself,
  instantly invalidating every record — and the SQLCipher key, which
  is VMK-derived — at once.
- **GDPR Art. 20 export** ([`export`]) — every readable record, as
  JSON, signed with the caller's dual (Ed25519 + ML-DSA-87) identity
  key, encrypted under an Argon2id key derived from a
  caller-supplied passphrase.

## Memory zeroization

VMK, every derived key, every DEK, and every returned plaintext are
`zeroize::Zeroizing`, consistent with
[`aegis-crypto`](https://crates.io/crates/aegis-crypto)'s own
discipline.

## Error handling

Nothing in this crate panics on data an attacker or a corrupted disk
controls. Malformed stored records, unreachable hardware key stores,
and SQLCipher failures all return [`error::VaultError`]
(`#[non_exhaustive]`).

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for noncommercial use;
commercial use requires a separate license.
```

- [ ] **Step 3: Create `crates/aegis-vault/LICENSE`**

Copy `crates/aegis-crypto/LICENSE` verbatim to `crates/aegis-vault/LICENSE` (identical PolyForm Noncommercial 1.0.0 text, same as every other crate in this workspace):

```bash
cp crates/aegis-crypto/LICENSE crates/aegis-vault/LICENSE
```

- [ ] **Step 4: Update `lib.rs`'s crate-level doc comment**

Replace `crates/aegis-vault/src/lib.rs`'s doc comment (the part above the `pub mod`/`mod` lines) with:

```rust
//! SQLCipher-encrypted local storage, hardware key isolation with a
//! strict zero-fallback policy, and GDPR Art. 17/20 erasure and
//! export.
//!
//! See `AEGIS.Plan.V0.2.md` Section 4 and
//! `docs/superpowers/specs/2026-09-11-aegis-vault-phase1-design.md`.
//! Depends on `aegis-crypto` only — no dependency on `aegis-ratchet`.
//!
//! Phase 1 narrows hardware-backed key isolation to Windows Credential
//! Manager and Linux Secret Service/Keyutils (both testable in this
//! environment); Android Keystore/StrongBox and Apple Secure Enclave
//! are deferred to a future plan behind the `HardwareKeyStore` trait
//! this crate already defines.
```

- [ ] **Step 5: Run the full workspace test suite and clippy**

Run: `cargo test --workspace 2>&1 | tail -30`
Expected: PASS — every crate's tests green, including all of `aegis-vault`'s.

Run: `cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -30`
Expected: zero warnings.

Run: `cargo doc -p aegis-vault --no-deps 2>&1 | tail -15`
Expected: builds clean, no broken intra-doc links (the README above references `[`keystore`]`, `[`vault`]`, `[`export`]`, `[`error::VaultError`]` — these need those modules to be `pub` or the links need adjusting to whatever visibility they actually ended up with; fix any broken links this surfaces before moving on).

- [ ] **Step 6: Commit**

```bash
git add crates/aegis-vault/Cargo.toml crates/aegis-vault/README.md crates/aegis-vault/LICENSE crates/aegis-vault/src/lib.rs
git commit -m "aegis-vault: add README, LICENSE, and crate metadata"
```

---

## Notes for the executor

- Every `temp_db_path` test helper writes to the OS temp directory and cleans up with `std::fs::remove_file` at the end of each test — if a test panics before cleanup, stale `.db` files can accumulate in temp; this is a known, low-stakes test-hygiene gap acceptable for Phase 1 (same category as similar gaps `aegis-ratchet`'s test suite has).
- First `cargo build`/`cargo test` after Task 1 will be slow (several minutes) — `bundled-sqlcipher-vendored-openssl` compiles both SQLCipher and OpenSSL from source. Subsequent builds are incremental and fast.
