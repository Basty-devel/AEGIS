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
// mod db;
// mod vault;
// mod export;

pub use error::VaultError;
// pub use vault::{Vault, VaultConfig};
