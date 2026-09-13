//! Runtime facade — owns the per-leaf state machines behind a single handle.
//!
//! [`AegisRuntime`] is the composition layer that a future `aegis-ffi` or
//! platform UI holds in one hand. It owns a [`aegis_vault_pqc::Vault`] and
//! (later) an [`aegis_ratchet::RatchetState`], with a single constructor
//! that enforces fail-closed init ordering: vault opens first, hardware
//! trust is verified, and only then does the ratchet layer initialise.

use std::path::PathBuf;

use crate::AegisError;

/// Configuration for [`AegisRuntime`].
///
/// All fields are mandatory — there are no optional paths or lazy-init
/// shenanigans. The runtime opens everything at construction time so
/// callers never see a half-initialised handle.
pub struct RuntimeConfig {
    /// Absolute path to the vault database.
    pub db_path: PathBuf,
    /// OS keyring service name for hardware-backed key storage.
    pub keyring_service_name: String,
}

/// AegisPQC runtime facade.
///
/// Holds the per-leaf state that the rest of the stack needs:
///
/// - **Vault** ([`aegis_vault_pqc::Vault`]) — hardware-backed envelope
///   encryption; opened first during construction so a missing trust
///   anchor fails closed before anything else is created.
/// - **Ratchet** (future) — double-ratchet state for forward-secrecy;
///   added once `aegis-ratchet` identity wire format stabilises.
/// - **Transport** (future) — Tor / mailbox plumbing; lives in `aegis-net`.
///
/// # Panic safety
///
/// `AegisRuntime` never panics on attacker-controlled,
/// relay-controlled, or vault-unavailable data. The only panics
/// reachable are OS-level RNG failure (`getrandom`) or unrecoverable
/// vault/SQL hard errors — neither is attacker-controlled.
///
/// # Zeroization
///
/// Secret material is held inside `zeroize::Zeroizing` wrappers owned
/// by the leaf crates. `AegisRuntime` adds no second zeroization layer;
/// stack/register copies outside `zeroize`'s reach are documented as
/// out of scope (same limitation the leaves document).
pub struct AegisRuntime {
    vault: aegis_vault_pqc::Vault,
}

impl AegisRuntime {
    /// Create a new runtime, enforcing fail-closed init ordering.
    ///
    /// 1. Opens the vault at `config.db_path`.
    /// 2. Verifies hardware trust (keyring / `HardwareKeyStoreUnavailable`
    ///    → [`AegisError::Vault`]).
    /// 3. Returns a fully-initialised handle.
    ///
    /// On any failure the constructor returns an error without creating
    /// or mutating anything — no half-opened state is exposed.
    pub fn new(config: RuntimeConfig) -> Result<Self, AegisError> {
        let vault_config = aegis_vault_pqc::VaultConfig {
            db_path: config.db_path,
            keyring_service_name: config.keyring_service_name,
        };
        let vault = aegis_vault_pqc::Vault::open(vault_config)?;
        Ok(Self { vault })
    }

    /// Borrow the vault (read-only).
    pub fn vault(&self) -> &aegis_vault_pqc::Vault {
        &self.vault
    }

    /// Borrow the vault (mutable).
    pub fn vault_mut(&mut self) -> &mut aegis_vault_pqc::Vault {
        &mut self.vault
    }
}
