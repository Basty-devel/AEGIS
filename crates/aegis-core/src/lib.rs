//! # AEGIS Core – Runtime Facade
//!
//! Implements **AEGIS Plan §8/§9 item 1**: a shared core library that composes the
//! leaf crates (`aegis-crypto`, `aegis-ratchet`, `aegis-vault-pqc`, `aegis-file`,
//! `aegis-net`) into a single, ergonomically-exported entry point. The core provides
//! a unified error type, a typed configuration, and the `AegisRuntime` handle that
//! owns the per-leaf state machines. It does **not** implement any new cryptography;
//! all algorithms are delegated to the leaf crates.
//!
//! * **Quick-start** – Construct a [`RuntimeConfig`] and call
//!   `AegisRuntime::new`. The constructor is fail-closed: the vault opens first;
//!   if hardware trust cannot be established the function returns
//!   [`AegisError::Vault`] without creating any other state.
//!
//! * **Zeroisation** – Secret material is stored inside the leaf crates'
//!   `zeroize::Zeroizing` wrappers. `AegisRuntime` does not add a second
//!   zeroisation layer; stack copies outside `zeroize` are documented as out-of-
//!   scope (the same limitation the leaves document).
//!
//! * **Panics** – No panic is reachable from attacker-controlled data. Only OS-
//!   level RNG or unrecoverable vault/SQL errors may panic, which are not under
//!   attacker control.
//!
//! * **Security disclaimer** – Re-exported from `aegis-crypto`.

#![warn(missing_docs)]

/// AegisPQC is NOT independently audited.
pub const SECURITY_DISCLAIMER: &str = aegis_crypto::SECURITY_DISCLAIMER;

pub mod error;
pub mod runtime;

pub use error::AegisError;
pub use runtime::{AegisRuntime, RuntimeConfig};

#[cfg(test)]
mod disclaimer_tests {
    use super::SECURITY_DISCLAIMER;

    #[test]
    fn disclaimer_states_not_audited() {
        assert!(SECURITY_DISCLAIMER.contains("NOT independently audited"));
    }
}
