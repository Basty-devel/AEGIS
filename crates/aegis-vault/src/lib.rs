//! SQLCipher-encrypted local storage with hardware-backed key isolation
//! and GDPR Art. 17/20 erasure and export.
//!
//! See `AEGIS.Plan.V0.2.md` Section 4 and
//! `docs/superpowers/specs/2026-09-11-aegis-vault-phase1-design.md`.
//! Depends on [`aegis_crypto`] only — no dependency on `aegis_ratchet`.
//!
//! Phase 1 narrows hardware-backed key isolation to Windows Credential
//! Manager and Linux Secret Service/Keyutils (both testable in this
//! environment); Android Keystore/StrongBox and Apple Secure Enclave
//! are deferred to a future plan behind the `HardwareKeyStore` trait
//! this crate already defines.
//!
//! # Architecture
//!
//! Every vault has a **Vault Master Key (VMK)** — a random 32-byte
//! secret stored in the OS credential store and never written to disk.
//! `Vault::open` fails outright if the credential store is unreachable:
//! there is no lower-security fallback path.
//!
//! Each database file uses SQLCipher (AES-256-CBC + HMAC-SHA512) as
//! a whole-file encryption layer keyed with `VMK`.  On top of that,
//! every record gets its own random Data Encryption Key (DEK), wrapped
//! under a VMK-derived key and encrypted with AES-256-GCM
//! ([`aegis_crypto::aead`]).  A canary row, encrypted under a separate
//! VMK-derived key, lets `Vault::open` distinguish "this vault was
//! never created" from "wrong VMK".
//!
//! # Quick start
//!
//! ```no_run
//! use aegis_vault_pqc::{Vault, VaultConfig};
//! use std::path::Path;
//!
//! let config = VaultConfig {
//!     db_path: Path::new("vault.db").to_path_buf(),
//!     keyring_service_name: "com.example.myapp".into(),
//! };
//!
//! let mut vault = Vault::open(config).expect("credential store unavailable");
//!
//! vault.put("messages", "alice@example.com", b"hello").unwrap();
//!
//! let plaintext = vault.get("messages", "alice@example.com").unwrap();
//! assert_eq!(&*plaintext.unwrap(), b"hello");
//! ```
//!
//! # Memory zeroization
//!
//! The VMK, every derived key, every DEK, and every plaintext returned
//! by [`Vault::get`] are [`zeroize::Zeroizing`].  Sensitive bytes are
//! wiped on drop, consistent with `aegis_crypto`'s own discipline.
//!
//! What this does **not** guarantee (and no pure-Rust crate can): that
//! the operating system never copied a secret elsewhere first.  Values
//! moved on the stack, spilled to registers, paged to swap, or
//! captured in a core dump are outside `zeroize`'s reach.
//!
//! # Panics
//!
//! Nothing in this crate panics on data an attacker or a corrupted disk
//! controls.  Malformed stored records, unreachable hardware key stores,
//! and SQLCipher failures all return [`error::VaultError`]
//! (`#[non_exhaustive]`).  The only panics are fail-closed reactions
//! to operating-system RNG failure (`getrandom`), documented at each
//! call site.
//!
//! # Security disclaimer
//!
//! This crate is **not independently audited**.  Do not rely on this
//! code for life-critical communications until a third-party
//! cryptographic audit has been completed.

#![warn(missing_docs)]

pub mod error;
mod db;
mod export;
mod kdf;
mod keystore;
mod vault;

pub use error::VaultError;
pub use vault::{Vault, VaultConfig};
