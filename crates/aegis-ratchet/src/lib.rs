//! PQ-X3DH handshake and Double Ratchet state machine. Pure,
//! synchronous, no I/O — see `AEGIS.Plan.V0.2.md` Section 3 (items
//! 1-3) and `docs/superpowers/specs/2026-09-06-aegis-ratchet-phase1-design.md`.
//!
//! Sender-keys groups and multi-device (spec §3.1/§3.2) are out of
//! scope for this crate as it stands — separate plans build on this
//! module's public API once it exists.

pub mod error;
pub mod kdf_chain;
pub mod prekey;

pub use error::RatchetError;
