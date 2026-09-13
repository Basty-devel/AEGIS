//! Federated mailbox networking, capability-token abuse resistance,
//! and Sealed Sender 2.0 for the AegisPQC messenger.
//!
//! See `AEGIS.Plan.V0.2.md` Section 6. This module currently implements
//! only Section 6.3's capability tokens and per-account rate limiting —
//! see `docs/superpowers/specs/2026-09-12-aegis-net-capability-tokens-design.md`.
//! Tor transport (6.1) is a separate, independent track — see
//! `docs/superpowers/specs/2026-09-12-aegis-net-transport-phase1-design.md`
//! — and the federated mailbox gossip protocol (6.2) is its own future
//! design once both exist.

#![warn(missing_docs)]

/// AegisPQC's networking layer is NOT independently audited. Do not
/// rely on this code for life-critical communications until a
/// third-party cryptographic audit has been completed. See
/// `AEGIS.Plan.V0.2.md`, document header, and Section 9.1.
pub const SECURITY_DISCLAIMER: &str = aegis_crypto::SECURITY_DISCLAIMER;

pub mod capability;
pub mod transport;
pub mod tor;
#[cfg(any(test, feature = "testing"))]
pub mod fake;
pub mod error;
pub mod rate_limit;
mod background;

pub use capability::{CapabilityToken, MAX_TOKEN_VALIDITY_SECONDS};
pub use error::NetError;
pub use rate_limit::{RateLimitDecision, RateLimiter};

#[cfg(test)]
mod tests {
    use super::SECURITY_DISCLAIMER;

    #[test]
    fn disclaimer_states_not_audited() {
        assert!(SECURITY_DISCLAIMER.contains("NOT independently audited"));
    }
}
