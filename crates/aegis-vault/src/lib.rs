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

pub mod error;
mod db;
pub mod export;
mod kdf;
pub mod keystore;
pub mod vault;

pub use error::VaultError;
pub use vault::{Vault, VaultConfig};
