# aegis-ratchet Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the pairwise PQ-X3DH handshake and Double Ratchet state machine in `aegis-ratchet` — a pure, synchronous, no-I/O crate that produces and consumes wire bytes, with no dependency on storage or transport.

**Architecture:** Six small modules, each with one responsibility: `error` (crate-wide error type), `kdf_chain` (the ratchet's own `KDF_RK`/`KDF_CK`, distinct from `aegis_crypto::kdf`), `prekey` (identity/pre-key types, bundle signing/verification, bundle wire format), `x3dh` (handshake shared-secret derivation, both sides), `state` (`RatchetState`, the DH ratchet step, message wire format), and `lib.rs` (the two public entry points: `encrypt_message`/`decrypt_message`).

**Tech Stack:** Rust, `aegis-crypto` (path dependency, same workspace) for every cryptographic primitive, plus direct `hkdf`/`sha2`/`hmac` for the ratchet-specific KDF chains (see Global Constraints).

**Spec:** [`docs/superpowers/specs/2026-09-06-aegis-ratchet-phase1-design.md`](../specs/2026-09-06-aegis-ratchet-phase1-design.md) (approved), which itself implements [`AEGIS.Plan.V0.2.md`](../../../AEGIS.Plan.V0.2.md) Section 3, items 1–3 only (not §3.1/§3.2 — groups and multi-device are separate, later plans).

## Global Constraints

- No I/O, no `async`, no dependency on `aegis-vault` or any storage/transport crate — `RatchetState` is a plain struct the caller persists however it wants (design §1).
- `#![deny(unsafe_code)]` from the workspace root applies; nothing in this plan needs `unsafe`.
- Manual byte encoding for every wire type — no `serde` in production dependencies, matching `aegis-crypto`'s convention and the design's explicit decision.
- **`kdf_chain::kdf_rk` cannot use `aegis_crypto::kdf::derive_key`**: that function hardcodes HKDF salt to `None` (see `crates/aegis-crypto/src/kdf.rs:69`), but Signal's `KDF_RK` construction (design §3.1) requires `salt = root_key`. `aegis-ratchet` therefore takes `hkdf`, `sha2`, and `hmac` as **direct** dependencies (same crates `aegis-crypto` already uses internally) and implements `KDF_RK`/`KDF_CK` itself. `aegis_crypto::kdf::derive_key` **is** used for X3DH's shared-secret derivation (Task 4/5) — that one's `salt = None` contract matches exactly.
- **`aegis_crypto::signature::DualKeyPair` has no DH capability** (it's Ed25519 + ML-DSA-87, signing only). X3DH needs each party to have a long-term brainpool512r1 keypair too, for the DH1/DH2/DH3 legs. This plan introduces `prekey::IdentityKeyPair { signing: DualKeyPair, ecdh: Brainpool512SecretKey }` (Task 3) to hold both — this is a necessary refinement the design doc didn't spell out at this precision; it doesn't change anything the design already approved, just makes explicit what "identity key" has to contain.
- Every zeroizable secret (root keys, chain keys, message keys, ephemeral private keys) is `Zeroizing`-wrapped, matching `aegis-crypto`'s policy exactly.
- Nothing panics on attacker-controlled bytes (peer bundles, wire messages, ciphertexts) — always `Result<_, RatchetError>`. The only panics are fail-closed OS RNG failures, inherited from the `aegis-crypto` calls that already panic on those (`Brainpool512SecretKey::generate`, `MlKem1024KeyPair::generate`, `ml_kem_encapsulate`).
- These are pre-1.0 crates with real API churn. If a step's exact method/type name has moved since this plan was written, that's the TDD "verify RED" step doing its job (a compile error naming a missing symbol) — check `cargo doc --open -p aegis-crypto` for the current name, don't treat it as the plan being wrong.
- No official KAT vectors exist for this protocol (it's a novel combination of standardized primitives, not itself standardized) — correctness rests on two-party agreement tests (Task 5, Task 11), not fixed vectors.

---

### Task 1: Crate setup, error type, module scaffolding

**Files:**
- Modify: `crates/aegis-ratchet/Cargo.toml`
- Modify: `crates/aegis-ratchet/src/lib.rs`
- Create: `crates/aegis-ratchet/src/error.rs`

**Interfaces:**
- Produces: `pub enum RatchetError` (with `From<aegis_crypto::CryptoError>`, `Display`, `std::error::Error`), re-exported as `aegis_ratchet::RatchetError`.

- [ ] **Step 1: Write the failing test**

In `crates/aegis-ratchet/src/error.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::RatchetError;

    #[test]
    fn crypto_error_converts_and_displays() {
        let crypto_err = aegis_crypto::CryptoError::InvalidPeerPublicKey;
        let err: RatchetError = crypto_err.clone().into();
        assert_eq!(err, RatchetError::Crypto(crypto_err));
        assert!(err.to_string().contains("brainpoolP512r1"));
    }

    #[test]
    fn errors_are_comparable() {
        assert_eq!(RatchetError::MalformedMessage, RatchetError::MalformedMessage);
        assert_ne!(RatchetError::MalformedMessage, RatchetError::UnknownMessage);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-ratchet crypto_error_converts_and_displays`
Expected: compile error — `error[E0433]: failed to resolve: use of undeclared crate or module aegis_ratchet` / `cannot find type RatchetError` (nothing exists yet).

- [ ] **Step 3: Add dependencies**

From the repo root (`C:\AEGIS`):

```bash
cargo add aegis-crypto --path crates/aegis-crypto -p aegis-ratchet
cargo add zeroize --features derive -p aegis-ratchet
cargo add hkdf -p aegis-ratchet
cargo add sha2 -p aegis-ratchet
cargo add hmac -p aegis-ratchet
cargo add getrandom -p aegis-ratchet
cargo add hex --dev -p aegis-ratchet
```

- [ ] **Step 4: Write minimal implementation**

`crates/aegis-ratchet/src/error.rs`:

```rust
//! Crate-wide error type for `aegis-ratchet`.
//!
//! Wraps `aegis_crypto::CryptoError` for errors propagated from
//! primitive calls, plus this crate's own protocol-level failure
//! modes. Nothing that can be driven by attacker-controlled bytes
//! (peer bundles, wire messages, tampered ciphertext) may panic — see
//! this plan's Global Constraints and `AEGIS.Plan.V0.2.md` Section 2.

use core::fmt;

/// Errors returned by `aegis-ratchet`'s fallible operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RatchetError {
    /// Propagated from an `aegis-crypto` primitive call (malformed
    /// peer public key, KEM key/ciphertext, etc.).
    Crypto(aegis_crypto::CryptoError),
    /// A pre-key bundle's fields were the wrong length or otherwise
    /// structurally invalid.
    MalformedPreKeyBundle,
    /// A pre-key bundle's signed pre-key signature did not verify
    /// against its claimed identity key.
    InvalidBundleSignature,
    /// A wire message's fields were the wrong length or otherwise
    /// structurally invalid.
    MalformedMessage,
    /// A message's number is below the current receive counter and
    /// not found in the skipped-key cache — already processed, or its
    /// key was evicted past `SkippedKeyCache`'s bound.
    UnknownMessage,
    /// AEAD authentication failed (tampered ciphertext, wrong key).
    DecryptionFailed,
    /// A single ratchet step's skip gap exceeded `MAX_SKIP` (design
    /// §5) — deriving that many keys in one jump is refused rather
    /// than performed, to bound the cost of a single call.
    SkippedKeyLimitExceeded,
}

impl From<aegis_crypto::CryptoError> for RatchetError {
    fn from(err: aegis_crypto::CryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(err) => write!(f, "aegis-crypto error: {err}"),
            Self::MalformedPreKeyBundle => f.write_str("pre-key bundle is malformed"),
            Self::InvalidBundleSignature => {
                f.write_str("pre-key bundle's signed pre-key signature does not verify")
            }
            Self::MalformedMessage => f.write_str("ratchet message is malformed"),
            Self::UnknownMessage => {
                f.write_str("message key not found (already processed or evicted)")
            }
            Self::DecryptionFailed => f.write_str("AEAD decryption/authentication failed"),
            Self::SkippedKeyLimitExceeded => {
                f.write_str("skip gap exceeds the maximum skipped-key derivation limit")
            }
        }
    }
}

impl std::error::Error for RatchetError {}
```

Replace `crates/aegis-ratchet/src/lib.rs`'s placeholder doc comment with:

```rust
//! PQ-X3DH handshake and Double Ratchet state machine. Pure,
//! synchronous, no I/O — see `AEGIS.Plan.V0.2.md` Section 3 (items
//! 1-3) and `docs/superpowers/specs/2026-09-06-aegis-ratchet-phase1-design.md`.
//!
//! Sender-keys groups and multi-device (spec §3.1/§3.2) are out of
//! scope for this crate as it stands — separate plans build on this
//! module's public API once it exists.

pub mod error;

pub use error::RatchetError;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p aegis-ratchet`
Expected: both tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/aegis-ratchet/Cargo.toml crates/aegis-ratchet/src/
git commit -m "aegis-ratchet: add dependencies, crate-wide error type"
```

---

### Task 2: Ratchet KDF chains (`KDF_RK` / `KDF_CK`)

**Files:**
- Create: `crates/aegis-ratchet/src/kdf_chain.rs`
- Modify: `crates/aegis-ratchet/src/lib.rs` (add `pub mod kdf_chain;`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `pub const ROOT_KEY_LEN: usize = 64`, `pub const CHAIN_KEY_LEN: usize = 64`, `pub const MESSAGE_KEY_LEN: usize = 32`; `pub fn kdf_rk(root_key: &[u8; ROOT_KEY_LEN], hybrid_shared_secret: &[u8]) -> (Zeroizing<[u8; ROOT_KEY_LEN]>, Zeroizing<[u8; CHAIN_KEY_LEN]>)`; `pub fn kdf_ck(chain_key: &[u8; CHAIN_KEY_LEN]) -> (Zeroizing<[u8; CHAIN_KEY_LEN]>, Zeroizing<[u8; MESSAGE_KEY_LEN]>)`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_rk_is_deterministic() {
        let root = [0x11u8; ROOT_KEY_LEN];
        let (rk1, ck1) = kdf_rk(&root, b"shared-secret");
        let (rk2, ck2) = kdf_rk(&root, b"shared-secret");
        assert_eq!(*rk1, *rk2);
        assert_eq!(*ck1, *ck2);
    }

    #[test]
    fn kdf_rk_new_root_key_differs_from_input_and_chain_key() {
        let root = [0x11u8; ROOT_KEY_LEN];
        let (new_root, chain_key) = kdf_rk(&root, b"shared-secret");
        assert_ne!(*new_root, root, "KDF_RK must not just echo its input");
        assert_ne!(&new_root[..], &chain_key[..], "root and chain outputs must differ");
    }

    #[test]
    fn kdf_rk_different_shared_secrets_diverge() {
        let root = [0x11u8; ROOT_KEY_LEN];
        let (rk_a, ck_a) = kdf_rk(&root, b"secret-a");
        let (rk_b, ck_b) = kdf_rk(&root, b"secret-b");
        assert_ne!(*rk_a, *rk_b);
        assert_ne!(*ck_a, *ck_b);
    }

    #[test]
    fn kdf_ck_new_chain_key_differs_from_message_key() {
        let chain = [0x22u8; CHAIN_KEY_LEN];
        let (new_chain, message_key) = kdf_ck(&chain);
        assert_ne!(&new_chain[..], &message_key[..]);
        assert_ne!(*new_chain, chain, "KDF_CK must not just echo its input");
    }

    #[test]
    fn kdf_ck_advances_differently_each_call() {
        let chain0 = [0x22u8; CHAIN_KEY_LEN];
        let (chain1, mk0) = kdf_ck(&chain0);
        let (chain2, mk1) = kdf_ck(&chain1);
        assert_ne!(*chain1, *chain2, "each chain step must move the chain forward");
        assert_ne!(*mk0, *mk1, "each step's message key must be unique");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-ratchet kdf_rk_is_deterministic`
Expected: compile error — `cannot find function kdf_rk in module kdf_chain` (module doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

```rust
//! The Double Ratchet's own root-key and chain-key KDFs (`KDF_RK`,
//! `KDF_CK`), adapted from Signal's Double Ratchet spec
//! (<https://signal.org/docs/specifications/doubleratchet/#external-functions>,
//! HMAC-SHA256 there, HMAC-SHA512 here for consistency with the rest
//! of `aegis-crypto`). Distinct from `aegis_crypto::kdf::derive_key`:
//! that function hardcodes HKDF salt to `None`, but `KDF_RK` requires
//! `salt = root_key` — see this plan's Global Constraints.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

/// Byte length of a ratchet root key.
pub const ROOT_KEY_LEN: usize = 64;
/// Byte length of a ratchet chain key.
pub const CHAIN_KEY_LEN: usize = 64;
/// Byte length of a derived message key (truncated for AES-256-GCM /
/// ChaCha20-Poly1305 keying).
pub const MESSAGE_KEY_LEN: usize = 32;

const RK_DOMAIN_LABEL: &[u8] = b"AEGIS-RATCHET-RK-v1";

/// The Double Ratchet's root-key KDF: advances `root_key` using a
/// fresh hybrid (ML-KEM-1024 + brainpool512r1) shared secret, per
/// design §3.1. Returns `(new_root_key, chain_key)`.
pub fn kdf_rk(
    root_key: &[u8; ROOT_KEY_LEN],
    hybrid_shared_secret: &[u8],
) -> (Zeroizing<[u8; ROOT_KEY_LEN]>, Zeroizing<[u8; CHAIN_KEY_LEN]>) {
    let hk = Hkdf::<Sha512>::new(Some(root_key), hybrid_shared_secret);
    let mut output = Zeroizing::new([0u8; ROOT_KEY_LEN + CHAIN_KEY_LEN]);
    hk.expand(RK_DOMAIN_LABEL, output.as_mut())
        .expect("128-byte expansion is far under HKDF-SHA512's 16320-byte limit");

    let mut new_root_key = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    let mut chain_key = Zeroizing::new([0u8; CHAIN_KEY_LEN]);
    new_root_key.copy_from_slice(&output[..ROOT_KEY_LEN]);
    chain_key.copy_from_slice(&output[ROOT_KEY_LEN..]);
    (new_root_key, chain_key)
}

/// The Double Ratchet's chain-key KDF: advances `chain_key` by one
/// message, per design §3.1. Returns `(new_chain_key, message_key)`.
pub fn kdf_ck(
    chain_key: &[u8; CHAIN_KEY_LEN],
) -> (Zeroizing<[u8; CHAIN_KEY_LEN]>, Zeroizing<[u8; MESSAGE_KEY_LEN]>) {
    let mut mac_for_chain =
        Hmac::<Sha512>::new_from_slice(chain_key).expect("HMAC-SHA512 accepts any key length");
    mac_for_chain.update(&[0x02]);
    let chain_result = mac_for_chain.finalize().into_bytes();
    let mut new_chain_key = Zeroizing::new([0u8; CHAIN_KEY_LEN]);
    new_chain_key.copy_from_slice(&chain_result);

    let mut mac_for_message =
        Hmac::<Sha512>::new_from_slice(chain_key).expect("HMAC-SHA512 accepts any key length");
    mac_for_message.update(&[0x01]);
    let message_result = mac_for_message.finalize().into_bytes();
    let mut message_key = Zeroizing::new([0u8; MESSAGE_KEY_LEN]);
    message_key.copy_from_slice(&message_result[..MESSAGE_KEY_LEN]);

    (new_chain_key, message_key)
}
```

Add `pub mod kdf_chain;` to `crates/aegis-ratchet/src/lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p aegis-ratchet kdf_chain::`
Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-ratchet/src/
git commit -m "aegis-ratchet: implement KDF_RK/KDF_CK ratchet chain KDFs"
```

---

### Task 3: Identity keys, pre-key bundles, signing/verification, wire format

**Files:**
- Create: `crates/aegis-ratchet/src/prekey.rs`
- Modify: `crates/aegis-ratchet/src/lib.rs` (add `pub mod prekey;`)

**Interfaces:**
- Consumes: `aegis_crypto::signature::{DualKeyPair, verify_dual}`, `aegis_crypto::ecdh::{Brainpool512SecretKey, brainpool512_diffie_hellman}`, `aegis_crypto::kem::MlKem1024KeyPair`, `RatchetError` (Task 1).
- Produces: `ECDH_PUBLIC_KEY_LEN`, `KEM_ENCAPSULATION_KEY_LEN`, `KEM_CIPHERTEXT_LEN`, `ED25519_PUBLIC_KEY_LEN`, `ML_DSA_87_PUBLIC_KEY_LEN`, `ED25519_SIGNATURE_LEN`, `ML_DSA_87_SIGNATURE_LEN` constants; `DualVerifyingKey`, `EncodedDualSignature`, `IdentityKeyPair`, `IdentityKeys`, `SignedPreKey`, `OneTimePreKey`, `PreKeyBundle` types; `IdentityKeyPair::generate()`/`.public_keys()`; `generate_signed_pre_key()`, `verify_signed_pre_key()`, `generate_one_time_pre_key()`; `PreKeyBundle::to_bytes()`/`from_bytes()`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_pre_key_verifies_against_its_own_identity() {
        let identity = IdentityKeyPair::generate();
        let (spk, _ecdh_priv, _kem_priv) = generate_signed_pre_key(&identity);
        assert!(verify_signed_pre_key(&identity.public_keys(), &spk));
    }

    #[test]
    fn signed_pre_key_fails_against_a_different_identity() {
        let identity = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();
        let (spk, _, _) = generate_signed_pre_key(&identity);
        assert!(!verify_signed_pre_key(&other.public_keys(), &spk));
    }

    #[test]
    fn tampered_signed_pre_key_ecdh_public_fails_verification() {
        let identity = IdentityKeyPair::generate();
        let (mut spk, _, _) = generate_signed_pre_key(&identity);
        spk.ecdh_public[0] ^= 0xFF;
        assert!(!verify_signed_pre_key(&identity.public_keys(), &spk));
    }

    #[test]
    fn bundle_round_trips_through_wire_bytes() {
        let identity = IdentityKeyPair::generate();
        let (signed_pre_key, _, _) = generate_signed_pre_key(&identity);
        let (one_time_pre_key, _, _) = generate_one_time_pre_key(7);
        let bundle = PreKeyBundle {
            identity: identity.public_keys(),
            signed_pre_key,
            one_time_pre_key: Some(one_time_pre_key),
        };

        let bytes = bundle.to_bytes();
        let decoded = PreKeyBundle::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.identity.ecdh_public, bundle.identity.ecdh_public);
        assert_eq!(decoded.signed_pre_key.ecdh_public, bundle.signed_pre_key.ecdh_public);
        assert_eq!(
            decoded.one_time_pre_key.as_ref().unwrap().id,
            bundle.one_time_pre_key.as_ref().unwrap().id,
        );
        assert!(verify_signed_pre_key(&decoded.identity, &decoded.signed_pre_key));
    }

    #[test]
    fn bundle_without_one_time_pre_key_round_trips() {
        let identity = IdentityKeyPair::generate();
        let (signed_pre_key, _, _) = generate_signed_pre_key(&identity);
        let bundle = PreKeyBundle {
            identity: identity.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };

        let decoded = PreKeyBundle::from_bytes(&bundle.to_bytes()).unwrap();
        assert!(decoded.one_time_pre_key.is_none());
    }

    #[test]
    fn truncated_bundle_bytes_are_rejected_without_panicking() {
        let identity = IdentityKeyPair::generate();
        let (signed_pre_key, _, _) = generate_signed_pre_key(&identity);
        let bundle = PreKeyBundle {
            identity: identity.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };
        let bytes = bundle.to_bytes();
        for cut in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert_eq!(
                PreKeyBundle::from_bytes(&bytes[..cut]).unwrap_err(),
                RatchetError::MalformedPreKeyBundle,
            );
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-ratchet prekey::`
Expected: compile error — `cannot find function generate_signed_pre_key` (module doesn't exist).

- [ ] **Step 3: Write minimal implementation**

```rust
//! Long-term identity keys and pre-key bundles for PQ-X3DH (design
//! §2). `aegis_crypto::signature::DualKeyPair` is signing-only
//! (Ed25519 + ML-DSA-87); X3DH additionally needs a long-term
//! brainpool512r1 keypair for its DH legs, so [`IdentityKeyPair`]
//! bundles both — see this plan's Global Constraints.

use crate::error::RatchetError;
use aegis_crypto::ecdh::Brainpool512SecretKey;
use aegis_crypto::kem::MlKem1024KeyPair;
use aegis_crypto::signature::{verify_dual, DualKeyPair, DualSignature};
use getrandom;

/// Uncompressed SEC1 brainpool512r1 public key length: `0x04 || X ||
/// Y`, each coordinate 64 bytes (RFC 5639 §3.7 field size).
pub const ECDH_PUBLIC_KEY_LEN: usize = 129;
/// FIPS 203 Table 3.
pub const KEM_ENCAPSULATION_KEY_LEN: usize = 1568;
/// FIPS 203 Table 3.
pub const KEM_CIPHERTEXT_LEN: usize = 1568;
/// RFC 8032.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// FIPS 204 Table 2 (ML-DSA-87 public key).
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
/// RFC 8032.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// FIPS 204 Table 2 (ML-DSA-87 signature).
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;

/// A dual (Ed25519 + ML-DSA-87) verifying key, fixed-size for wire
/// encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualVerifyingKey {
    pub ed25519: [u8; ED25519_PUBLIC_KEY_LEN],
    pub ml_dsa87: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
}

/// A dual signature, fixed-size for wire encoding (contrast with
/// `aegis_crypto::signature::DualSignature`, whose `ml_dsa87` field is
/// a `Vec<u8>` — this type is the frozen-length wire form of it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedDualSignature {
    pub ed25519: [u8; ED25519_SIGNATURE_LEN],
    pub ml_dsa87: [u8; ML_DSA_87_SIGNATURE_LEN],
}

impl TryFrom<&DualSignature> for EncodedDualSignature {
    type Error = RatchetError;

    fn try_from(sig: &DualSignature) -> Result<Self, RatchetError> {
        Ok(Self {
            ed25519: sig.ed25519,
            ml_dsa87: sig
                .ml_dsa87
                .as_slice()
                .try_into()
                .map_err(|_| RatchetError::MalformedMessage)?,
        })
    }
}

/// A party's full long-term identity: a signing keypair plus a
/// separate brainpool512r1 DH keypair (X3DH needs both; see this
/// plan's Global Constraints).
pub struct IdentityKeyPair {
    pub signing: DualKeyPair,
    pub ecdh: Brainpool512SecretKey,
}

/// The public half of [`IdentityKeyPair`], as published in a
/// [`PreKeyBundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeys {
    pub verifying: DualVerifyingKey,
    pub ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
}

impl IdentityKeyPair {
    /// Generate a fresh long-term identity.
    pub fn generate() -> Self {
        Self {
            signing: DualKeyPair::generate(),
            ecdh: Brainpool512SecretKey::generate(),
        }
    }

    pub fn public_keys(&self) -> IdentityKeys {
        IdentityKeys {
            verifying: DualVerifyingKey {
                ed25519: self.signing.ed25519_public_bytes(),
                ml_dsa87: self
                    .signing
                    .ml_dsa87_public_bytes()
                    .try_into()
                    .expect("ml_dsa87_public_bytes is always ML_DSA_87_PUBLIC_KEY_LEN bytes"),
            },
            ecdh_public: self
                .ecdh
                .public_key_bytes()
                .try_into()
                .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes for brainpool512r1"),
        }
    }
}

/// A signed pre-key: fresh ECDH + KEM material, signed by the identity
/// key, published as part of a [`PreKeyBundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPreKey {
    pub ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    pub kem_encapsulation_key: [u8; KEM_ENCAPSULATION_KEY_LEN],
    pub signature: EncodedDualSignature,
}

fn signed_pre_key_signing_input(
    ecdh_public: &[u8; ECDH_PUBLIC_KEY_LEN],
    kem_encapsulation_key: &[u8; KEM_ENCAPSULATION_KEY_LEN],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(ECDH_PUBLIC_KEY_LEN + KEM_ENCAPSULATION_KEY_LEN);
    input.extend_from_slice(ecdh_public);
    input.extend_from_slice(kem_encapsulation_key);
    input
}

/// Generate a signed pre-key under `identity`. Returns the public
/// [`SignedPreKey`] to publish plus the two private keypairs the
/// generating party must retain to answer an incoming X3DH handshake
/// (Task 5).
pub fn generate_signed_pre_key(
    identity: &IdentityKeyPair,
) -> (SignedPreKey, Brainpool512SecretKey, MlKem1024KeyPair) {
    let ecdh = Brainpool512SecretKey::generate();
    let kem = MlKem1024KeyPair::generate();
    let ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN] = ecdh
        .public_key_bytes()
        .try_into()
        .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes");
    let kem_encapsulation_key: [u8; KEM_ENCAPSULATION_KEY_LEN] = kem
        .encapsulation_key_bytes()
        .try_into()
        .expect("encapsulation_key_bytes is always KEM_ENCAPSULATION_KEY_LEN bytes");

    let signing_input = signed_pre_key_signing_input(&ecdh_public, &kem_encapsulation_key);
    let signature = (&identity.signing.sign(&signing_input))
        .try_into()
        .expect("DualKeyPair::sign always produces ML_DSA_87_SIGNATURE_LEN bytes");

    (
        SignedPreKey {
            ecdh_public,
            kem_encapsulation_key,
            signature,
        },
        ecdh,
        kem,
    )
}

/// Verify a [`SignedPreKey`]'s signature against `identity`.
pub fn verify_signed_pre_key(identity: &IdentityKeys, spk: &SignedPreKey) -> bool {
    let signing_input = signed_pre_key_signing_input(&spk.ecdh_public, &spk.kem_encapsulation_key);
    let sig = DualSignature {
        ed25519: spk.signature.ed25519,
        ml_dsa87: spk.signature.ml_dsa87.to_vec(),
    };
    verify_dual(
        &identity.verifying.ed25519,
        &identity.verifying.ml_dsa87,
        &signing_input,
        &sig,
    )
}

/// A single-use pre-key: fresh, unsigned ECDH + KEM material, consumed
/// on use (design §2.1 — matches Signal's OPK).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimePreKey {
    pub id: u32,
    pub ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    pub kem_encapsulation_key: [u8; KEM_ENCAPSULATION_KEY_LEN],
}

/// Generate a one-time pre-key with the given bookkeeping `id`.
/// Returns the public [`OneTimePreKey`] plus the private keypairs the
/// generating party must retain (and discard after one use).
pub fn generate_one_time_pre_key(id: u32) -> (OneTimePreKey, Brainpool512SecretKey, MlKem1024KeyPair) {
    let ecdh = Brainpool512SecretKey::generate();
    let kem = MlKem1024KeyPair::generate();
    let ecdh_public = ecdh
        .public_key_bytes()
        .try_into()
        .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes");
    let kem_encapsulation_key = kem
        .encapsulation_key_bytes()
        .try_into()
        .expect("encapsulation_key_bytes is always KEM_ENCAPSULATION_KEY_LEN bytes");
    (
        OneTimePreKey {
            id,
            ecdh_public,
            kem_encapsulation_key,
        },
        ecdh,
        kem,
    )
}

/// What one party publishes so others can start an X3DH handshake
/// with them (design §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreKeyBundle {
    pub identity: IdentityKeys,
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_key: Option<OneTimePreKey>,
}

impl PreKeyBundle {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.identity.verifying.ed25519);
        out.extend_from_slice(&self.identity.verifying.ml_dsa87);
        out.extend_from_slice(&self.identity.ecdh_public);
        out.extend_from_slice(&self.signed_pre_key.ecdh_public);
        out.extend_from_slice(&self.signed_pre_key.kem_encapsulation_key);
        out.extend_from_slice(&self.signed_pre_key.signature.ed25519);
        out.extend_from_slice(&self.signed_pre_key.signature.ml_dsa87);
        match &self.one_time_pre_key {
            None => out.push(0x00),
            Some(otpk) => {
                out.push(0x01);
                out.extend_from_slice(&otpk.id.to_be_bytes());
                out.extend_from_slice(&otpk.ecdh_public);
                out.extend_from_slice(&otpk.kem_encapsulation_key);
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut cursor = ByteCursor::new(bytes);
        let identity = IdentityKeys {
            verifying: DualVerifyingKey {
                ed25519: cursor.take_array::<ED25519_PUBLIC_KEY_LEN>()?,
                ml_dsa87: cursor.take_array::<ML_DSA_87_PUBLIC_KEY_LEN>()?,
            },
            ecdh_public: cursor.take_array::<ECDH_PUBLIC_KEY_LEN>()?,
        };
        let signed_pre_key = SignedPreKey {
            ecdh_public: cursor.take_array::<ECDH_PUBLIC_KEY_LEN>()?,
            kem_encapsulation_key: cursor.take_array::<KEM_ENCAPSULATION_KEY_LEN>()?,
            signature: EncodedDualSignature {
                ed25519: cursor.take_array::<ED25519_SIGNATURE_LEN>()?,
                ml_dsa87: cursor.take_array::<ML_DSA_87_SIGNATURE_LEN>()?,
            },
        };
        let has_otpk = cursor.take_byte()?;
        let one_time_pre_key = match has_otpk {
            0x00 => None,
            0x01 => Some(OneTimePreKey {
                id: u32::from_be_bytes(cursor.take_array::<4>()?),
                ecdh_public: cursor.take_array::<ECDH_PUBLIC_KEY_LEN>()?,
                kem_encapsulation_key: cursor.take_array::<KEM_ENCAPSULATION_KEY_LEN>()?,
            }),
            _ => return Err(RatchetError::MalformedPreKeyBundle),
        };
        Ok(Self {
            identity,
            signed_pre_key,
            one_time_pre_key,
        })
    }
}

/// A minimal forward-only byte reader used by every wire-format
/// `from_bytes` in this crate: takes fixed-size chunks off the front,
/// erroring (never panicking) on truncation.
pub(crate) struct ByteCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> ByteCursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    pub(crate) fn take_array<const N: usize>(&mut self) -> Result<[u8; N], RatchetError> {
        if self.remaining.len() < N {
            return Err(RatchetError::MalformedPreKeyBundle);
        }
        let (chunk, rest) = self.remaining.split_at(N);
        self.remaining = rest;
        Ok(chunk.try_into().expect("split_at(N) guarantees N bytes"))
    }

    pub(crate) fn take_byte(&mut self) -> Result<u8, RatchetError> {
        let arr = self.take_array::<1>()?;
        Ok(arr[0])
    }

    pub(crate) fn take_vec(&mut self, len: usize) -> Result<Vec<u8>, RatchetError> {
        if self.remaining.len() < len {
            return Err(RatchetError::MalformedPreKeyBundle);
        }
        let (chunk, rest) = self.remaining.split_at(len);
        self.remaining = rest;
        Ok(chunk.to_vec())
    }

    pub(crate) fn remaining(&self) -> &[u8] {
        self.remaining
    }
}
```

Add `pub mod prekey;` to `crates/aegis-ratchet/src/lib.rs`.

**Note on `ByteCursor`:** this is written here because it's `prekey`'s first consumer, but it's `pub(crate)` and used again in Task 6 (`RatchetHeader`/`RatchetMessage`) and Task 4 (`AegisX3DHInitialMessage`) — later tasks import it via `crate::prekey::ByteCursor`, they don't redefine it. `take_vec`'s error is `MalformedPreKeyBundle` here for simplicity (only `prekey.rs` uses it in this task); Task 4/6 wrap `ByteCursor` failures into their own more specific `RatchetError::MalformedMessage` at their call sites via `.map_err`, not by changing this method.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p aegis-ratchet prekey::`
Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-ratchet/src/
git commit -m "aegis-ratchet: add identity keys, pre-key bundles, wire format"
```

---

### Task 4: X3DH initiator side

**Files:**
- Create: `crates/aegis-ratchet/src/x3dh.rs`
- Modify: `crates/aegis-ratchet/src/lib.rs` (add `pub mod x3dh;`)

**Interfaces:**
- Consumes: `prekey::{IdentityKeyPair, IdentityKeys, PreKeyBundle, ByteCursor, ECDH_PUBLIC_KEY_LEN, KEM_ENCAPSULATION_KEY_LEN, KEM_CIPHERTEXT_LEN, ED25519_PUBLIC_KEY_LEN, ML_DSA_87_PUBLIC_KEY_LEN, DualVerifyingKey}` (Task 3), `kdf_chain::ROOT_KEY_LEN` (Task 2), `aegis_crypto::{ecdh::{Brainpool512SecretKey, brainpool512_diffie_hellman}, kem::ml_kem_encapsulate, kdf::derive_key, version::ProtocolVersion}`, `RatchetError` (Task 1).
- Produces: `pub struct X3DHPreamble` (every handshake field except the first ciphertext message); `pub fn initiate_x3dh(my_identity: &IdentityKeyPair, peer_bundle: &PreKeyBundle, protocol_version: ProtocolVersion) -> Result<(Zeroizing<[u8; ROOT_KEY_LEN]>, X3DHPreamble, [u8; ECDH_PUBLIC_KEY_LEN]), RatchetError>` — the third element is Alice's ephemeral ECDH public key, which Task 6 needs again (as her first ratchet public key) without re-deriving it from the preamble bytes. `X3DHPreamble::to_bytes()`/`from_bytes()`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::prekey::{generate_signed_pre_key, IdentityKeyPair, PreKeyBundle};
    use aegis_crypto::version::ProtocolVersion;

    fn bob_bundle_and_identity() -> (PreKeyBundle, IdentityKeyPair) {
        let bob = IdentityKeyPair::generate();
        let (signed_pre_key, _ecdh_priv, _kem_priv) = generate_signed_pre_key(&bob);
        let bundle = PreKeyBundle {
            identity: bob.public_keys(),
            signed_pre_key,
            one_time_pre_key: None,
        };
        (bundle, bob)
    }

    #[test]
    fn initiate_produces_a_root_key_and_preamble() {
        let alice = IdentityKeyPair::generate();
        let (bob_bundle, _bob) = bob_bundle_and_identity();

        let (root_key, preamble, alice_ephemeral_public) =
            initiate_x3dh(&alice, &bob_bundle, ProtocolVersion::V1).unwrap();

        assert_ne!(*root_key, [0u8; kdf_chain::ROOT_KEY_LEN]);
        assert_eq!(preamble.alice_ephemeral_ecdh_public, alice_ephemeral_public);
        assert!(preamble.used_one_time_pre_key_id.is_none());
    }

    #[test]
    fn preamble_round_trips_through_wire_bytes() {
        let alice = IdentityKeyPair::generate();
        let (bob_bundle, _bob) = bob_bundle_and_identity();
        let (_root_key, preamble, _) = initiate_x3dh(&alice, &bob_bundle, ProtocolVersion::V1).unwrap();

        let decoded = X3DHPreamble::from_bytes(&preamble.to_bytes()).unwrap();
        assert_eq!(decoded.alice_ephemeral_ecdh_public, preamble.alice_ephemeral_ecdh_public);
        assert_eq!(decoded.kem_ciphertext_signed, preamble.kem_ciphertext_signed);
        assert_eq!(decoded.used_one_time_pre_key_id, preamble.used_one_time_pre_key_id);
    }

    #[test]
    fn rejects_a_bundle_with_an_invalid_signature() {
        let alice = IdentityKeyPair::generate();
        let (mut bob_bundle, _bob) = bob_bundle_and_identity();
        bob_bundle.signed_pre_key.ecdh_public[0] ^= 0xFF; // now the signature no longer matches

        assert_eq!(
            initiate_x3dh(&alice, &bob_bundle, ProtocolVersion::V1).unwrap_err(),
            RatchetError::InvalidBundleSignature,
        );
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-ratchet x3dh::`
Expected: compile error — `cannot find function initiate_x3dh` (module doesn't exist).

- [ ] **Step 3: Write minimal implementation**

```rust
//! PQ-X3DH handshake (design §2). Extends Signal's X3DH
//! (<https://signal.org/docs/specifications/x3dh/>) from a 3-DH
//! combiner to a hybrid 4-leg combiner: the three classical DH legs
//! are unchanged, plus one ML-KEM-1024 encapsulation leg (two, if the
//! bundle includes a one-time pre-key).

use crate::error::RatchetError;
use crate::kdf_chain::ROOT_KEY_LEN;
use crate::prekey::{
    verify_signed_pre_key, ByteCursor, IdentityKeyPair, PreKeyBundle, DualVerifyingKey,
    ECDH_PUBLIC_KEY_LEN, ED25519_PUBLIC_KEY_LEN, KEM_CIPHERTEXT_LEN, ML_DSA_87_PUBLIC_KEY_LEN,
};
use aegis_crypto::ecdh::{brainpool512_diffie_hellman, Brainpool512SecretKey};
use aegis_crypto::kdf::derive_key;
use aegis_crypto::kem::ml_kem_encapsulate;
use aegis_crypto::version::ProtocolVersion;
use zeroize::Zeroizing;

const X3DH_DOMAIN_LABEL: &[u8] = b"AEGIS-X3DH-v1";

/// Everything a X3DH initial handshake message carries except the
/// first actual ciphertext (Task 6 combines this with a
/// `RatchetMessage` for transmission).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X3DHPreamble {
    pub protocol_version: u8,
    pub alice_identity: DualVerifyingKey,
    pub alice_identity_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    pub alice_ephemeral_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    pub kem_ciphertext_signed: [u8; KEM_CIPHERTEXT_LEN],
    pub used_one_time_pre_key_id: Option<u32>,
    pub kem_ciphertext_onetime: Option<[u8; KEM_CIPHERTEXT_LEN]>,
}

impl X3DHPreamble {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.protocol_version);
        out.extend_from_slice(&self.alice_identity.ed25519);
        out.extend_from_slice(&self.alice_identity.ml_dsa87);
        out.extend_from_slice(&self.alice_identity_ecdh_public);
        out.extend_from_slice(&self.alice_ephemeral_ecdh_public);
        out.extend_from_slice(&self.kem_ciphertext_signed);
        match self.used_one_time_pre_key_id {
            None => out.push(0x00),
            Some(id) => {
                out.push(0x01);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(
                    self.kem_ciphertext_onetime
                        .as_ref()
                        .expect("used_one_time_pre_key_id.is_some() implies kem_ciphertext_onetime.is_some()"),
                );
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut cursor = ByteCursor::new(bytes);
        let protocol_version = cursor.take_byte().map_err(|_| RatchetError::MalformedMessage)?;
        let alice_identity = DualVerifyingKey {
            ed25519: cursor
                .take_array::<ED25519_PUBLIC_KEY_LEN>()
                .map_err(|_| RatchetError::MalformedMessage)?,
            ml_dsa87: cursor
                .take_array::<ML_DSA_87_PUBLIC_KEY_LEN>()
                .map_err(|_| RatchetError::MalformedMessage)?,
        };
        let alice_identity_ecdh_public = cursor
            .take_array::<ECDH_PUBLIC_KEY_LEN>()
            .map_err(|_| RatchetError::MalformedMessage)?;
        let alice_ephemeral_ecdh_public = cursor
            .take_array::<ECDH_PUBLIC_KEY_LEN>()
            .map_err(|_| RatchetError::MalformedMessage)?;
        let kem_ciphertext_signed = cursor
            .take_array::<KEM_CIPHERTEXT_LEN>()
            .map_err(|_| RatchetError::MalformedMessage)?;
        let has_otpk = cursor.take_byte().map_err(|_| RatchetError::MalformedMessage)?;
        let (used_one_time_pre_key_id, kem_ciphertext_onetime) = match has_otpk {
            0x00 => (None, None),
            0x01 => {
                let id = u32::from_be_bytes(
                    cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?,
                );
                let ct = cursor
                    .take_array::<KEM_CIPHERTEXT_LEN>()
                    .map_err(|_| RatchetError::MalformedMessage)?;
                (Some(id), Some(ct))
            }
            _ => return Err(RatchetError::MalformedMessage),
        };
        Ok(Self {
            protocol_version,
            alice_identity,
            alice_identity_ecdh_public,
            alice_ephemeral_ecdh_public,
            kem_ciphertext_signed,
            used_one_time_pre_key_id,
            kem_ciphertext_onetime,
        })
    }
}

/// Compute Alice's X3DH shared secret and preamble against Bob's
/// `peer_bundle`. Returns `(root_key, preamble, alice_ephemeral_ecdh_public)`
/// — the caller (Task 6) uses `alice_ephemeral_ecdh_public` again as
/// Alice's first ratchet public key, so it's returned directly rather
/// than making Task 6 re-parse it out of `preamble`.
///
/// # Errors
///
/// Returns [`RatchetError::InvalidBundleSignature`] if
/// `peer_bundle.signed_pre_key`'s signature does not verify against
/// `peer_bundle.identity`. Propagates [`RatchetError::Crypto`] from
/// malformed key material.
pub fn initiate_x3dh(
    my_identity: &IdentityKeyPair,
    peer_bundle: &PreKeyBundle,
    protocol_version: ProtocolVersion,
) -> Result<(Zeroizing<[u8; ROOT_KEY_LEN]>, X3DHPreamble, [u8; ECDH_PUBLIC_KEY_LEN]), RatchetError> {
    if !verify_signed_pre_key(&peer_bundle.identity, &peer_bundle.signed_pre_key) {
        return Err(RatchetError::InvalidBundleSignature);
    }

    let ephemeral = Brainpool512SecretKey::generate();
    let alice_ephemeral_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN] = ephemeral
        .public_key_bytes()
        .try_into()
        .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes");

    let dh1 = brainpool512_diffie_hellman(&my_identity.ecdh, &peer_bundle.signed_pre_key.ecdh_public)?;
    let dh2 = brainpool512_diffie_hellman(&ephemeral, &peer_bundle.identity.ecdh_public)?;
    let dh3 = brainpool512_diffie_hellman(&ephemeral, &peer_bundle.signed_pre_key.ecdh_public)?;
    let (kem_ciphertext_signed_vec, kem_ss_signed) =
        ml_kem_encapsulate(&peer_bundle.signed_pre_key.kem_encapsulation_key)?;
    let kem_ciphertext_signed: [u8; KEM_CIPHERTEXT_LEN] = kem_ciphertext_signed_vec
        .try_into()
        .expect("ml_kem_encapsulate ciphertext is always KEM_CIPHERTEXT_LEN bytes");

    let mut ikm = Vec::with_capacity(3 * 64 + 32 + 32);
    ikm.extend_from_slice(&*dh1);
    ikm.extend_from_slice(&*dh2);
    ikm.extend_from_slice(&*dh3);
    ikm.extend_from_slice(&*kem_ss_signed);

    let (used_one_time_pre_key_id, kem_ciphertext_onetime) =
        if let Some(otpk) = &peer_bundle.one_time_pre_key {
            let (ct_vec, ss) = ml_kem_encapsulate(&otpk.kem_encapsulation_key)?;
            let ct: [u8; KEM_CIPHERTEXT_LEN] = ct_vec
                .try_into()
                .expect("ml_kem_encapsulate ciphertext is always KEM_CIPHERTEXT_LEN bytes");
            ikm.extend_from_slice(&*ss);
            (Some(otpk.id), Some(ct))
        } else {
            (None, None)
        };

    let alice_identity_pub = my_identity.public_keys();
    let mut alice_identity_bytes = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ML_DSA_87_PUBLIC_KEY_LEN);
    alice_identity_bytes.extend_from_slice(&alice_identity_pub.verifying.ed25519);
    alice_identity_bytes.extend_from_slice(&alice_identity_pub.verifying.ml_dsa87);
    let mut bob_identity_bytes = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ML_DSA_87_PUBLIC_KEY_LEN);
    bob_identity_bytes.extend_from_slice(&peer_bundle.identity.verifying.ed25519);
    bob_identity_bytes.extend_from_slice(&peer_bundle.identity.verifying.ml_dsa87);

    let mut root_key = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    derive_key(
        &ikm,
        X3DH_DOMAIN_LABEL,
        protocol_version as u8,
        &alice_identity_bytes,
        &bob_identity_bytes,
        root_key.as_mut(),
    )?;

    let preamble = X3DHPreamble {
        protocol_version: protocol_version as u8,
        alice_identity: alice_identity_pub.verifying,
        alice_identity_ecdh_public: alice_identity_pub.ecdh_public,
        alice_ephemeral_ecdh_public,
        kem_ciphertext_signed,
        used_one_time_pre_key_id,
        kem_ciphertext_onetime,
    };

    Ok((root_key, preamble, alice_ephemeral_ecdh_public))
}
```

Add `pub mod x3dh;` to `crates/aegis-ratchet/src/lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p aegis-ratchet x3dh::`
Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-ratchet/src/
git commit -m "aegis-ratchet: implement X3DH initiator side"
```

---

### Task 5: X3DH responder side + two-party agreement test

**Files:**
- Modify: `crates/aegis-ratchet/src/x3dh.rs`

**Interfaces:**
- Consumes: everything from Task 4, plus `aegis_crypto::kem::{ml_kem_decapsulate, MlKem1024KeyPair}`.
- Produces: `pub fn respond_to_x3dh(my_identity: &IdentityKeyPair, my_signed_pre_key_ecdh: &Brainpool512SecretKey, my_signed_pre_key_kem: &MlKem1024KeyPair, my_one_time_pre_key: Option<(&Brainpool512SecretKey, &MlKem1024KeyPair)>, preamble: &X3DHPreamble) -> Result<Zeroizing<[u8; ROOT_KEY_LEN]>, RatchetError>`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn both_sides_derive_the_same_root_key() {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob);
    let bundle = PreKeyBundle {
        identity: bob.public_keys(),
        signed_pre_key,
        one_time_pre_key: None,
    };

    let (alice_root_key, preamble, _alice_ephemeral) =
        initiate_x3dh(&alice, &bundle, ProtocolVersion::V1).unwrap();

    let bob_root_key =
        respond_to_x3dh(&bob, &bob_spk_ecdh, &bob_spk_kem, None, &preamble).unwrap();

    assert_eq!(*alice_root_key, *bob_root_key);
}

#[test]
fn both_sides_agree_when_a_one_time_pre_key_is_used() {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob);
    let (one_time_pre_key, bob_otpk_ecdh, bob_otpk_kem) = generate_one_time_pre_key(1);
    let bundle = PreKeyBundle {
        identity: bob.public_keys(),
        signed_pre_key,
        one_time_pre_key: Some(one_time_pre_key),
    };

    let (alice_root_key, preamble, _) = initiate_x3dh(&alice, &bundle, ProtocolVersion::V1).unwrap();
    assert!(preamble.used_one_time_pre_key_id.is_some());

    let bob_root_key = respond_to_x3dh(
        &bob,
        &bob_spk_ecdh,
        &bob_spk_kem,
        Some((&bob_otpk_ecdh, &bob_otpk_kem)),
        &preamble,
    )
    .unwrap();

    assert_eq!(*alice_root_key, *bob_root_key);
}

#[test]
fn a_third_party_derives_a_different_root_key() {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let mallory = IdentityKeyPair::generate();
    let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob);
    let bundle = PreKeyBundle {
        identity: bob.public_keys(),
        signed_pre_key,
        one_time_pre_key: None,
    };

    let (alice_root_key, preamble, _) = initiate_x3dh(&alice, &bundle, ProtocolVersion::V1).unwrap();
    let (_mallory_root_key, mallory_preamble, _) =
        initiate_x3dh(&mallory, &bundle, ProtocolVersion::V1).unwrap();

    let bob_root_key_from_mallory =
        respond_to_x3dh(&bob, &bob_spk_ecdh, &bob_spk_kem, None, &mallory_preamble).unwrap();

    assert_ne!(*alice_root_key, *bob_root_key_from_mallory);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-ratchet both_sides_derive_the_same_root_key`
Expected: compile error — `cannot find function respond_to_x3dh`.

- [ ] **Step 3: Write minimal implementation**

Append to `crates/aegis-ratchet/src/x3dh.rs`:

```rust
use aegis_crypto::kem::{ml_kem_decapsulate, MlKem1024KeyPair};

/// Compute Bob's X3DH shared secret from Alice's `preamble`, using the
/// private keypairs matching whichever pre-keys the preamble says were
/// used. Must derive the identical root key `initiate_x3dh` derived
/// for the same handshake (verified by this task's agreement tests).
///
/// # Errors
///
/// Propagates [`RatchetError::Crypto`] from malformed key material.
/// Does not itself re-verify a bundle signature (Bob is answering his
/// own published bundle, not re-checking it) — signature verification
/// happens only on the initiating side, against the bundle it received
/// (Task 4).
pub fn respond_to_x3dh(
    my_identity: &IdentityKeyPair,
    my_signed_pre_key_ecdh: &Brainpool512SecretKey,
    my_signed_pre_key_kem: &MlKem1024KeyPair,
    my_one_time_pre_key: Option<(&Brainpool512SecretKey, &MlKem1024KeyPair)>,
    preamble: &X3DHPreamble,
) -> Result<Zeroizing<[u8; ROOT_KEY_LEN]>, RatchetError> {
    let dh1 = brainpool512_diffie_hellman(my_signed_pre_key_ecdh, &preamble.alice_identity_ecdh_public)?;
    let dh2 = brainpool512_diffie_hellman(&my_identity.ecdh, &preamble.alice_ephemeral_ecdh_public)?;
    let dh3 = brainpool512_diffie_hellman(my_signed_pre_key_ecdh, &preamble.alice_ephemeral_ecdh_public)?;
    let kem_ss_signed = ml_kem_decapsulate(my_signed_pre_key_kem, &preamble.kem_ciphertext_signed)?;

    let mut ikm = Vec::with_capacity(3 * 64 + 32 + 32);
    ikm.extend_from_slice(&*dh1);
    ikm.extend_from_slice(&*dh2);
    ikm.extend_from_slice(&*dh3);
    ikm.extend_from_slice(&*kem_ss_signed);

    if let (Some(ct), Some((_otpk_ecdh, otpk_kem))) =
        (&preamble.kem_ciphertext_onetime, my_one_time_pre_key)
    {
        let ss = ml_kem_decapsulate(otpk_kem, ct)?;
        ikm.extend_from_slice(&*ss);
    }

    let my_identity_pub = my_identity.public_keys();
    let mut bob_identity_bytes = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ML_DSA_87_PUBLIC_KEY_LEN);
    bob_identity_bytes.extend_from_slice(&my_identity_pub.verifying.ed25519);
    bob_identity_bytes.extend_from_slice(&my_identity_pub.verifying.ml_dsa87);
    let mut alice_identity_bytes = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ML_DSA_87_PUBLIC_KEY_LEN);
    alice_identity_bytes.extend_from_slice(&preamble.alice_identity.ed25519);
    alice_identity_bytes.extend_from_slice(&preamble.alice_identity.ml_dsa87);

    let mut root_key = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    derive_key(
        &ikm,
        X3DH_DOMAIN_LABEL,
        preamble.protocol_version,
        &alice_identity_bytes,
        &bob_identity_bytes,
        root_key.as_mut(),
    )?;

    Ok(root_key)
}
```

Note the IKM leg order and `derive_key`'s `pubkey_a`/`pubkey_b` argument order both stay **(Alice, Bob)** — `initiate_x3dh` passes `(alice_identity_bytes, bob_identity_bytes)` and so does `respond_to_x3dh` (`alice_identity_bytes` from `preamble`, `bob_identity_bytes` from `my_identity_pub`). This is what makes the two sides agree: `derive_key`'s `info` binds `pubkey_a` and `pubkey_b` positionally, not by whichever side is calling.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p aegis-ratchet x3dh::`
Expected: all 6 tests (3 from Task 4, 3 from this task) pass.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-ratchet/src/x3dh.rs
git commit -m "aegis-ratchet: implement X3DH responder side, verify two-party agreement"
```

---

### Task 6: `RatchetState`, initial construction, message wire format

**Files:**
- Create: `crates/aegis-ratchet/src/state.rs`
- Modify: `crates/aegis-ratchet/src/lib.rs` (add `pub mod state;`)

**Interfaces:**
- Consumes: `kdf_chain::{ROOT_KEY_LEN, CHAIN_KEY_LEN, kdf_rk}` (Task 2), `prekey::{ByteCursor, ECDH_PUBLIC_KEY_LEN, KEM_ENCAPSULATION_KEY_LEN, KEM_CIPHERTEXT_LEN}` (Task 3), `x3dh::X3DHPreamble` (Task 4/5), `aegis_crypto::{ecdh::Brainpool512SecretKey, kem::MlKem1024KeyPair}`, `RatchetError` (Task 1).
- Produces: `pub struct RatchetState` (opaque fields, `pub(crate)` — no public field access, matching design §1's "caller only sees serialized bytes"); `pub struct RatchetHeader`; `pub struct RatchetMessage`; `RatchetState::from_x3dh_initiator(root_key, peer_signed_pre_key_ecdh_public, peer_signed_pre_key_kem_public) -> Self`; `RatchetState::from_x3dh_responder(root_key, peer_ephemeral_ecdh_public, my_signed_pre_key_ecdh, my_signed_pre_key_kem) -> Self`; `RatchetState::to_bytes()`/`from_bytes()`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf_chain::ROOT_KEY_LEN;
    use aegis_crypto::ecdh::Brainpool512SecretKey;
    use aegis_crypto::kem::MlKem1024KeyPair;

    #[test]
    fn initiator_state_has_no_sending_or_receiving_chain_yet() {
        let root_key = [0x33u8; ROOT_KEY_LEN];
        let bob_ecdh = Brainpool512SecretKey::generate();
        let bob_kem = MlKem1024KeyPair::generate();
        let state = RatchetState::from_x3dh_initiator(
            root_key,
            bob_ecdh.public_key_bytes().try_into().unwrap(),
            bob_kem.encapsulation_key_bytes().try_into().unwrap(),
        );
        // Neither side has sent/received yet -- confirmed indirectly via
        // round-trip below; direct field access is deliberately not
        // public (design 1: RatchetState is opaque outside this crate).
        let bytes = state.to_bytes();
        assert!(RatchetState::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn state_round_trips_through_wire_bytes() {
        let root_key = [0x33u8; ROOT_KEY_LEN];
        let bob_ecdh = Brainpool512SecretKey::generate();
        let bob_kem = MlKem1024KeyPair::generate();
        let state = RatchetState::from_x3dh_initiator(
            root_key,
            bob_ecdh.public_key_bytes().try_into().unwrap(),
            bob_kem.encapsulation_key_bytes().try_into().unwrap(),
        );

        let bytes = state.to_bytes();
        let decoded = RatchetState::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.to_bytes(), bytes, "round trip must be exact");
    }

    #[test]
    fn truncated_state_bytes_are_rejected_without_panicking() {
        let root_key = [0x33u8; ROOT_KEY_LEN];
        let bob_ecdh = Brainpool512SecretKey::generate();
        let bob_kem = MlKem1024KeyPair::generate();
        let state = RatchetState::from_x3dh_initiator(
            root_key,
            bob_ecdh.public_key_bytes().try_into().unwrap(),
            bob_kem.encapsulation_key_bytes().try_into().unwrap(),
        );
        let bytes = state.to_bytes();
        assert_eq!(
            RatchetState::from_bytes(&bytes[..bytes.len() / 2]).unwrap_err(),
            RatchetError::MalformedMessage,
        );
    }

    #[test]
    fn header_round_trips_through_wire_bytes() {
        let header = RatchetHeader {
            ratchet_ecdh_public: [0x01u8; ECDH_PUBLIC_KEY_LEN],
            ratchet_kem_public: [0x02u8; KEM_ENCAPSULATION_KEY_LEN],
            kem_ciphertext: Some([0x03u8; KEM_CIPHERTEXT_LEN]),
            message_number: 42,
            previous_chain_length: 7,
        };
        let bytes = header.to_bytes();
        let decoded = RatchetHeader::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_without_kem_ciphertext_round_trips() {
        let header = RatchetHeader {
            ratchet_ecdh_public: [0x01u8; ECDH_PUBLIC_KEY_LEN],
            ratchet_kem_public: [0x02u8; KEM_ENCAPSULATION_KEY_LEN],
            kem_ciphertext: None,
            message_number: 0,
            previous_chain_length: 0,
        };
        let decoded = RatchetHeader::from_bytes(&header.to_bytes()).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn message_round_trips_through_wire_bytes() {
        let message = RatchetMessage {
            header: RatchetHeader {
                ratchet_ecdh_public: [0x01u8; ECDH_PUBLIC_KEY_LEN],
                ratchet_kem_public: [0x02u8; KEM_ENCAPSULATION_KEY_LEN],
                kem_ciphertext: None,
                message_number: 5,
                previous_chain_length: 3,
            },
            ciphertext: b"hello aegis ratchet".to_vec(),
        };
        let decoded = RatchetMessage::from_bytes(&message.to_bytes()).unwrap();
        assert_eq!(decoded.header, message.header);
        assert_eq!(decoded.ciphertext, message.ciphertext);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-ratchet state::`
Expected: compile error — `cannot find struct RatchetState`.

- [ ] **Step 3: Write minimal implementation**

```rust
//! The Double Ratchet's state machine: `RatchetState`, its wire
//! serialization, and the `RatchetHeader`/`RatchetMessage` wire types
//! for encrypted messages. See design §3, §4.3.

use crate::error::RatchetError;
use crate::kdf_chain::{kdf_rk, CHAIN_KEY_LEN, ROOT_KEY_LEN};
use crate::prekey::{ByteCursor, ECDH_PUBLIC_KEY_LEN, KEM_CIPHERTEXT_LEN, KEM_ENCAPSULATION_KEY_LEN};
use aegis_crypto::ecdh::Brainpool512SecretKey;
use aegis_crypto::kem::MlKem1024KeyPair;
use zeroize::Zeroizing;

/// One side of the ratchet: a chain key that advances by one message
/// per `KDF_CK` call (design §3.1).
pub(crate) struct ChainState {
    pub(crate) chain_key: Zeroizing<[u8; CHAIN_KEY_LEN]>,
}

/// The full Double Ratchet session state (design §3). Every field is
/// crate-private: callers outside this crate only ever see
/// [`RatchetState::to_bytes`]/[`RatchetState::from_bytes`] — this is
/// what design §1 means by "a pure state machine that produces and
/// consumes bytes."
pub struct RatchetState {
    pub(crate) root_key: Zeroizing<[u8; ROOT_KEY_LEN]>,
    pub(crate) sending_chain: Option<ChainState>,
    pub(crate) receiving_chain: Option<ChainState>,
    pub(crate) self_ratchet_ecdh: Brainpool512SecretKey,
    pub(crate) self_ratchet_kem: MlKem1024KeyPair,
    pub(crate) peer_ratchet_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    pub(crate) peer_ratchet_kem_public: [u8; KEM_ENCAPSULATION_KEY_LEN],
    pub(crate) send_message_number: u32,
    pub(crate) receive_message_number: u32,
    pub(crate) previous_chain_length: u32,
}

impl RatchetState {
    /// Build Alice's initial state right after [`crate::x3dh::initiate_x3dh`].
    /// Bob's signed pre-key doubles as his first ratchet public keys —
    /// standard X3DH-to-Double-Ratchet handoff. `sending_chain` starts
    /// `None`; [`crate::state::RatchetState`]'s first
    /// [`crate::encrypt_message`] call starts it via the same "start a
    /// sending chain" step the DH ratchet uses (Task 7/8).
    pub fn from_x3dh_initiator(
        root_key: [u8; ROOT_KEY_LEN],
        peer_signed_pre_key_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
        peer_signed_pre_key_kem_public: [u8; KEM_ENCAPSULATION_KEY_LEN],
    ) -> Self {
        Self {
            root_key: Zeroizing::new(root_key),
            sending_chain: None,
            receiving_chain: None,
            self_ratchet_ecdh: Brainpool512SecretKey::generate(),
            self_ratchet_kem: MlKem1024KeyPair::generate(),
            peer_ratchet_ecdh_public: peer_signed_pre_key_ecdh_public,
            peer_ratchet_kem_public: peer_signed_pre_key_kem_public,
            send_message_number: 0,
            receive_message_number: 0,
            previous_chain_length: 0,
        }
    }

    /// Build Bob's initial state right after
    /// [`crate::x3dh::respond_to_x3dh`].
    ///
    /// `receiving_chain` starts `None`, **not** populated here, even
    /// though Bob already has a DH output available (his signed
    /// pre-key's private ECDH scalar against Alice's ephemeral public
    /// key). The reason: the ratchet's hybrid secret always needs
    /// *both* legs (design §3 item 2 — "every roundtrip injects a new
    /// ML-KEM-1024 encapsulation paired with a brainpool512r1
    /// exchange"), and Bob's matching KEM leg is the ciphertext
    /// Alice's *first ratchet message* carries — not the X3DH
    /// preamble's `kem_ciphertext_signed`, which was already consumed
    /// inside [`crate::x3dh::respond_to_x3dh`]'s root-key derivation
    /// and cannot be reused for a second, different KDF call. So Bob
    /// cannot finish deriving `receiving_chain` until he has decrypted
    /// that first message — which needs a `RatchetState` to exist
    /// first. This function resolves that ordering the same way
    /// Signal resolves the equivalent handoff: leave `receiving_chain`
    /// `None`, and let [`Self::decrypt`]'s existing "unseen ratchet
    /// public key → run a DH ratchet step first" logic (Task 7/9)
    /// populate it from Alice's first message's header, exactly as it
    /// would for any later ratchet step.
    ///
    /// `self_ratchet_ecdh`/`self_ratchet_kem` are Bob's *existing*
    /// signed pre-key private keypair, reused rather than freshly
    /// generated: Bob hasn't sent anything yet, so there's no reason
    /// to rotate. `sending_chain` starts `None` until he does.
    pub fn from_x3dh_responder(
        root_key: [u8; ROOT_KEY_LEN],
        peer_ephemeral_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
        my_signed_pre_key_ecdh: Brainpool512SecretKey,
        my_signed_pre_key_kem: MlKem1024KeyPair,
    ) -> Self {
        Self {
            root_key: Zeroizing::new(root_key),
            sending_chain: None,
            receiving_chain: None,
            self_ratchet_ecdh: my_signed_pre_key_ecdh,
            self_ratchet_kem: my_signed_pre_key_kem,
            peer_ratchet_ecdh_public: peer_ephemeral_ecdh_public,
            // Bob doesn't have Alice's ratchet KEM public key yet --
            // only her first message's header carries it. Zeroed here;
            // Task 7's DH ratchet step overwrites it (and populates
            // receiving_chain) the moment decrypt_message sees that
            // header, before this placeholder value is ever used for
            // anything.
            peer_ratchet_kem_public: [0u8; KEM_ENCAPSULATION_KEY_LEN],
            send_message_number: 0,
            receive_message_number: 0,
            previous_chain_length: 0,
        }
    }
}
```

**Before writing `RatchetState::to_bytes`/`from_bytes`, this task needs two small additions to `aegis-crypto` first.** `Brainpool512SecretKey` and `MlKem1024KeyPair` expose no way to export their **private** key bytes — by design, since that would work against their own zeroization guarantees — so serializing `RatchetState` cannot round-trip `self_ratchet_ecdh`/`self_ratchet_kem` through those types' own APIs as they stand today. This is a real gap the design doc's §1 ("`RatchetState` serializes to/from a flat byte format") didn't anticipate at this precision, surfaced here because Task 6 is the first task that actually has to serialize the struct.

**Decided:** extend `aegis-crypto` with additive, non-breaking export methods (not the alternative of holding raw seeds inside `aegis-ratchet` and duplicating key-generation logic there). Do this as its own TDD sub-step in `crates/aegis-crypto`, following that crate's existing test/doc-comment style exactly, **before** returning to `aegis-ratchet`'s `state.rs`:

- [ ] **Step 3a: Add `Brainpool512SecretKey::to_bytes` to `aegis-crypto`**

In `crates/aegis-crypto/src/ecdh.rs`'s test module, add a failing test first:

```rust
    #[test]
    fn secret_key_round_trips_through_to_bytes() {
        let original = Brainpool512SecretKey::generate();
        let bytes = original.to_bytes();
        let restored = Brainpool512SecretKey::from_bytes(&bytes).unwrap();
        // Compare via a shared peer rather than field access (the
        // inner SecretKey has no PartialEq) -- if the round trip
        // preserved the scalar, both sides compute the same shared
        // secret with a third party.
        let peer = Brainpool512SecretKey::generate();
        let original_shared = brainpool512_diffie_hellman(&original, &peer.public_key_bytes()).unwrap();
        let restored_shared = brainpool512_diffie_hellman(&restored, &peer.public_key_bytes()).unwrap();
        assert_eq!(*original_shared, *restored_shared);
    }
```

Run `cargo test -p aegis-crypto secret_key_round_trips_through_to_bytes` — expect a compile error (`to_bytes`/`from_bytes` don't exist yet). Then add to `Brainpool512SecretKey`'s `impl` block:

```rust
    /// The raw 64-byte private scalar, for callers that need to
    /// persist this key themselves (e.g. `aegis-ratchet`'s
    /// `RatchetState` serialization). Wrapped in [`Zeroizing`] like
    /// every other secret this crate returns.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let field_bytes = self.0.to_bytes();
        let mut out = Zeroizing::new([0u8; 64]);
        out.copy_from_slice(&field_bytes);
        out
    }

    /// Reconstruct a key from bytes produced by [`Self::to_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidPeerPublicKey`] if `bytes` is not
    /// a valid brainpool512r1 scalar. (Reusing that variant rather
    /// than adding a new one: both mean "not a valid point/scalar
    /// encoding for this curve," and `CryptoError` is
    /// `#[non_exhaustive]` specifically so callers don't need to
    /// exhaustively match every variant -- see `error.rs`'s own
    /// module doc.)
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, CryptoError> {
        let field_bytes = elliptic_curve::FieldBytes::<BrainpoolP512r1>::from(*bytes);
        SecretKey::<BrainpoolP512r1>::from_bytes(&field_bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidPeerPublicKey)
    }
```

Run `cargo test -p aegis-crypto` — expect all tests (existing plus the new one) to pass. Commit:

```bash
git add crates/aegis-crypto/src/ecdh.rs
git commit -m "aegis-crypto: add Brainpool512SecretKey::to_bytes/from_bytes"
```

- [ ] **Step 3b: Add seed export/reconstruction to `MlKem1024KeyPair`**

`MlKem1024KeyPair::generate` currently samples a seed, builds the keypair, then zeroizes the seed (`crates/aegis-crypto/src/kem.rs`) — the seed itself is never retained. Retaining it is the smallest change that supports export: add a `seed: Zeroizing<ml_kem::Seed>` field, populate it in `generate`, and add `to_seed_bytes`/`from_seed_bytes`.

In `crates/aegis-crypto/src/kem.rs`'s test module, add a failing test first:

```rust
    #[test]
    fn keypair_round_trips_through_seed_bytes() {
        let original = MlKem1024KeyPair::generate();
        let seed = original.to_seed_bytes();
        let restored = MlKem1024KeyPair::from_seed_bytes(&seed);
        assert_eq!(
            original.encapsulation_key_bytes(),
            restored.encapsulation_key_bytes(),
            "reconstructing from the same seed must give the same public key",
        );
    }
```

Run `cargo test -p aegis-crypto keypair_round_trips_through_seed_bytes` — expect a compile error. Then, in `kem.rs`:

1. Add the field (remove the `#[zeroize(skip)]`-adjacent comment's implication that only two fields exist):

```rust
#[derive(ZeroizeOnDrop)]
pub struct MlKem1024KeyPair {
    decapsulation_key: ml_kem::DecapsulationKey<MlKem1024>,
    #[zeroize(skip)]
    encapsulation_key: EncapsulationKey<MlKem1024>,
    seed: Zeroizing<ml_kem::Seed>,
}
```

2. Change `generate()` to retain the seed instead of zeroizing it (delete the `seed.as_mut_slice().zeroize();` line and the comment immediately above it explaining why it used to be wiped — that reasoning no longer applies once the seed is a kept, zeroize-on-drop field instead of a stack temporary) and store it:

```rust
    pub fn generate() -> Self {
        let mut seed = ml_kem::Seed::default();
        getrandom::fill(seed.as_mut_slice()).expect("OS RNG failure");
        let (decapsulation_key, encapsulation_key) = MlKem1024::from_seed(&seed);
        Self {
            decapsulation_key,
            encapsulation_key,
            seed: Zeroizing::new(seed),
        }
    }
```

3. Add the export/reconstruction methods:

```rust
    /// The raw 64-byte seed this keypair was generated from, for
    /// callers that need to persist this key themselves (e.g.
    /// `aegis-ratchet`'s `RatchetState` serialization).
    pub fn to_seed_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out.copy_from_slice(self.seed.as_slice());
        out
    }

    /// Reconstruct a keypair from a seed produced by
    /// [`Self::to_seed_bytes`]. Infallible: every 64-byte value is a
    /// valid ML-KEM-1024 seed (FIPS 203's `from_seed` has no rejection
    /// step, unlike brainpool512r1's scalar sampling).
    pub fn from_seed_bytes(bytes: &[u8; 64]) -> Self {
        let mut seed = ml_kem::Seed::default();
        seed.as_mut_slice().copy_from_slice(bytes);
        let (decapsulation_key, encapsulation_key) = MlKem1024::from_seed(&seed);
        Self {
            decapsulation_key,
            encapsulation_key,
            seed: Zeroizing::new(seed),
        }
    }
```

Run `cargo test -p aegis-crypto` — expect all tests to pass, including the existing `keypair_zeroizes_on_drop` C2 regression guard (the new `seed` field is a `Zeroizing<_>`, which is itself `Zeroize`, so the `#[derive(ZeroizeOnDrop)]` on the struct still holds — this is worth double-checking explicitly since it's exactly the kind of thing that guard exists to catch). Commit:

```bash
git add crates/aegis-crypto/src/kem.rs
git commit -m "aegis-crypto: retain and expose MlKem1024KeyPair's generating seed"
```

- [ ] **Step 3c: Bump `aegis-crypto`'s version and update `aegis-ratchet`'s dependency**

`crates/aegis-crypto/Cargo.toml`: bump `version` from `0.1.3` to `0.1.4` (new public methods, no breaking change — a minor-within-0.x patch-equivalent bump). `crates/aegis-ratchet/Cargo.toml`: if it pins an exact `aegis-crypto` version, bump it to match; a `path` dependency (this plan's Task 1 default) needs no change. Publish `aegis-crypto` 0.1.4 to crates.io the same way 0.1.1/0.1.3 were published (this step needs your human partner's crates.io credentials — hand it back to them with the `cargo publish -p aegis-crypto` command rather than attempting it).

Now, back in `aegis-ratchet`'s `state.rs`, write `to_bytes`/`from_bytes` covering every `RatchetState` field: `root_key` (64 bytes), `sending_chain`/`receiving_chain` (a presence byte, then 64 bytes of `chain_key` if present), `self_ratchet_ecdh` (via the new `to_bytes`/`from_bytes`, 64 bytes) and `self_ratchet_kem` (via the new `to_seed_bytes`/`from_seed_bytes`, 64 bytes), `peer_ratchet_ecdh_public`, `peer_ratchet_kem_public`, and the three `u32` counters big-endian — each field guarded the same truncation-safe way `PreKeyBundle::from_bytes` (Task 3) is, then re-run this task's `state::` tests.

`RatchetHeader`/`RatchetMessage` have no such blocker (they carry only public material) — implement those now:

```rust
/// One ratchet message's header (design §4.3). `ratchet_kem_public` is
/// always present (an "I'm listening on this" announcement, mirroring
/// `ratchet_ecdh_public`); `kem_ciphertext` is present only on the
/// first message of a newly started sending chain -- see the design
/// doc's §4.3 for why KEM's encapsulate-only asymmetry means it can't
/// mirror the ECDH field exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetHeader {
    pub ratchet_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    pub ratchet_kem_public: [u8; KEM_ENCAPSULATION_KEY_LEN],
    pub kem_ciphertext: Option<[u8; KEM_CIPHERTEXT_LEN]>,
    pub message_number: u32,
    pub previous_chain_length: u32,
}

impl RatchetHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.ratchet_ecdh_public);
        out.extend_from_slice(&self.ratchet_kem_public);
        match self.kem_ciphertext {
            None => out.push(0x00),
            Some(ct) => {
                out.push(0x01);
                out.extend_from_slice(&ct);
            }
        }
        out.extend_from_slice(&self.message_number.to_be_bytes());
        out.extend_from_slice(&self.previous_chain_length.to_be_bytes());
        out
    }

    pub fn from_bytes(cursor: &mut ByteCursor) -> Result<Self, RatchetError> {
        let ratchet_ecdh_public = cursor
            .take_array::<ECDH_PUBLIC_KEY_LEN>()
            .map_err(|_| RatchetError::MalformedMessage)?;
        let ratchet_kem_public = cursor
            .take_array::<KEM_ENCAPSULATION_KEY_LEN>()
            .map_err(|_| RatchetError::MalformedMessage)?;
        let has_ct = cursor.take_byte().map_err(|_| RatchetError::MalformedMessage)?;
        let kem_ciphertext = match has_ct {
            0x00 => None,
            0x01 => Some(
                cursor
                    .take_array::<KEM_CIPHERTEXT_LEN>()
                    .map_err(|_| RatchetError::MalformedMessage)?,
            ),
            _ => return Err(RatchetError::MalformedMessage),
        };
        let message_number = u32::from_be_bytes(
            cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?,
        );
        let previous_chain_length = u32::from_be_bytes(
            cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?,
        );
        Ok(Self {
            ratchet_ecdh_public,
            ratchet_kem_public,
            kem_ciphertext,
            message_number,
            previous_chain_length,
        })
    }
}

/// A full encrypted ratchet message: header plus AEAD ciphertext
/// (design §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetMessage {
    pub header: RatchetHeader,
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.header.to_bytes();
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut cursor = ByteCursor::new(bytes);
        let header = RatchetHeader::from_bytes(&mut cursor)?;
        let len_bytes = cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let ciphertext = cursor.take_vec(len).map_err(|_| RatchetError::MalformedMessage)?;
        Ok(Self { header, ciphertext })
    }
}
```

Add `pub mod state;` to `crates/aegis-ratchet/src/lib.rs`.

- [ ] **Step 4: Resolve the `RatchetState` serialization blocker, then implement `to_bytes`/`from_bytes`**

Bring the option-1-vs-option-2 question above to your human partner. Once decided:

- **If option 1 (extend `aegis-crypto`)**: add `Brainpool512SecretKey::to_bytes(&self) -> Zeroizing<[u8; 64]>` (wrapping `elliptic_curve::SecretKey::to_bytes()`) and a seed-retaining `MlKem1024KeyPair` constructor pair (`from_seed_bytes`/`seed_bytes` or equivalent) to `aegis-crypto`, each with its own TDD cycle in `crates/aegis-crypto/src/ecdh.rs`/`kem.rs` (write a failing test there first, following that crate's own existing test style), then use them here.
- **If option 2 (raw seeds in `RatchetState`)**: change `self_ratchet_ecdh`/`self_ratchet_kem` fields to `Zeroizing<[u8; 32]>`/`Zeroizing<[u8; 64]>` seeds, add small private helpers in `state.rs` that reconstruct a `Brainpool512SecretKey`/`MlKem1024KeyPair` from a seed on demand (following the exact same rejection-sampling-from-seed / `MlKem1024::from_seed` pattern `aegis-crypto`'s own `generate()` methods use, since a deterministic-from-seed reconstruction needs the identical construction path), and update every call site in Tasks 7-11 that currently expects those fields to be the `aegis-crypto` types directly.

Either way, finish `to_bytes`/`from_bytes` for every `RatchetState` field, then:

Run: `cargo test -p aegis-ratchet state::`
Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-ratchet/src/
git commit -m "aegis-ratchet: add RatchetState, wire format for header/message"
```

---

### Task 7: DH ratchet step

**Files:**
- Modify: `crates/aegis-ratchet/src/state.rs`

**Interfaces:**
- Consumes: everything from Task 6, `aegis_crypto::kem::{ml_kem_encapsulate, ml_kem_decapsulate}`, `aegis_crypto::ecdh::brainpool512_diffie_hellman`.
- Produces: `pub(crate) fn RatchetState::dh_ratchet_step(&mut self, header: &RatchetHeader) -> Result<(), RatchetError>` (receiving side — advances `receiving_chain` and, if needed, starts a fresh `sending_chain`); `pub(crate) fn RatchetState::start_sending_chain(&mut self) -> Result<RatchetHeader, RatchetError>` (used both here and by `encrypt_message`, Task 8).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn dh_ratchet_step_updates_receiving_chain_from_a_new_peer_header() {
    let root_key = [0x33u8; ROOT_KEY_LEN];
    let bob_spk_ecdh = Brainpool512SecretKey::generate();
    let bob_spk_kem = MlKem1024KeyPair::generate();
    let mut alice_state = RatchetState::from_x3dh_initiator(
        root_key,
        bob_spk_ecdh.public_key_bytes().try_into().unwrap(),
        bob_spk_kem.encapsulation_key_bytes().try_into().unwrap(),
    );

    // Simulate a header arriving with a ratchet public key alice_state
    // hasn't ratcheted to yet: encapsulate against alice's OWN current
    // ratchet KEM public key, as a peer starting a new chain toward
    // her would.
    let sender_ecdh = Brainpool512SecretKey::generate();
    let (kem_ciphertext, _ss) =
        aegis_crypto::kem::ml_kem_encapsulate(&alice_state.self_ratchet_kem.encapsulation_key_bytes())
            .unwrap();
    let header = RatchetHeader {
        ratchet_ecdh_public: sender_ecdh.public_key_bytes().try_into().unwrap(),
        ratchet_kem_public: MlKem1024KeyPair::generate().encapsulation_key_bytes().try_into().unwrap(),
        kem_ciphertext: Some(kem_ciphertext.try_into().unwrap()),
        message_number: 0,
        previous_chain_length: 0,
    };

    assert!(alice_state.receiving_chain.is_none());
    alice_state.dh_ratchet_step(&header).unwrap();
    assert!(alice_state.receiving_chain.is_some());
    assert_eq!(alice_state.peer_ratchet_ecdh_public, header.ratchet_ecdh_public);
    assert_eq!(alice_state.peer_ratchet_kem_public, header.ratchet_kem_public);
    assert_eq!(alice_state.receive_message_number, 0);
}

#[test]
fn start_sending_chain_populates_the_chain_and_returns_a_matching_header() {
    let root_key = [0x33u8; ROOT_KEY_LEN];
    let bob_spk_ecdh = Brainpool512SecretKey::generate();
    let bob_spk_kem = MlKem1024KeyPair::generate();
    let mut alice_state = RatchetState::from_x3dh_initiator(
        root_key,
        bob_spk_ecdh.public_key_bytes().try_into().unwrap(),
        bob_spk_kem.encapsulation_key_bytes().try_into().unwrap(),
    );

    assert!(alice_state.sending_chain.is_none());
    let header = alice_state.start_sending_chain().unwrap();
    assert!(alice_state.sending_chain.is_some());
    assert!(header.kem_ciphertext.is_some(), "first message of a new chain must carry the KEM leg");
    assert_eq!(header.ratchet_ecdh_public, alice_state.self_ratchet_ecdh.public_key_bytes().as_slice());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-ratchet dh_ratchet_step_updates_receiving_chain_from_a_new_peer_header`
Expected: compile error — `no method named dh_ratchet_step found`.

- [ ] **Step 3: Write minimal implementation**

Append to the `impl RatchetState` block in `crates/aegis-ratchet/src/state.rs`:

```rust
    /// Compute this ratchet step's hybrid shared secret: a
    /// brainpool512r1 DH output concatenated with an ML-KEM-1024
    /// shared secret, per design §3 item 2 ("every message roundtrip
    /// injects a new ML-KEM-1024 encapsulation paired with a
    /// brainpool512r1 ephemeral exchange").
    fn hybrid_ratchet_secret(
        ecdh_shared: &[u8; 64],
        kem_shared: &[u8; 32],
    ) -> Zeroizing<[u8; 96]> {
        let mut out = Zeroizing::new([0u8; 96]);
        out[..64].copy_from_slice(ecdh_shared);
        out[64..].copy_from_slice(kem_shared);
        out
    }

    /// A DH ratchet step, triggered when `header` carries a peer
    /// ratchet public key not yet seen (design §3.2). Advances
    /// `receiving_chain` using `header`'s KEM ciphertext (which must
    /// be present -- the first message of any new peer chain always
    /// carries one, by construction of [`Self::start_sending_chain`]),
    /// generates a fresh self-ratchet keypair, and starts a new
    /// `sending_chain` toward the peer's newly announced public keys.
    pub(crate) fn dh_ratchet_step(&mut self, header: &RatchetHeader) -> Result<(), RatchetError> {
        let kem_ciphertext = header.kem_ciphertext.ok_or(RatchetError::MalformedMessage)?;

        let ecdh_shared =
            aegis_crypto::ecdh::brainpool512_diffie_hellman(&self.self_ratchet_ecdh, &header.ratchet_ecdh_public)?;
        let kem_shared = aegis_crypto::kem::ml_kem_decapsulate(&self.self_ratchet_kem, &kem_ciphertext)?;
        let hybrid_secret = Self::hybrid_ratchet_secret(&ecdh_shared, &kem_shared);

        let (new_root_key, chain_key) = kdf_rk(&self.root_key, hybrid_secret.as_ref());
        self.root_key = new_root_key;
        self.receiving_chain = Some(ChainState { chain_key });
        self.receive_message_number = 0;
        self.previous_chain_length = self.send_message_number;

        self.peer_ratchet_ecdh_public = header.ratchet_ecdh_public;
        self.peer_ratchet_kem_public = header.ratchet_kem_public;

        // A fresh keypair for our own next sending chain -- generated
        // now so the *next* start_sending_chain call (from
        // encrypt_message, whenever we next send) uses it, matching
        // Signal's "generate immediately on receiving a new ratchet
        // key" step.
        self.self_ratchet_ecdh = Brainpool512SecretKey::generate();
        self.self_ratchet_kem = MlKem1024KeyPair::generate();
        self.sending_chain = None;
        self.send_message_number = 0;

        Ok(())
    }

    /// Start a fresh sending chain toward `peer_ratchet_ecdh_public`/
    /// `peer_ratchet_kem_public`, encapsulating a fresh KEM ciphertext
    /// against the peer's current KEM public key (design §3.1/§4.3).
    /// Returns the header the resulting message must carry -- this is
    /// the *only* header shape that ever carries `kem_ciphertext:
    /// Some(_)`, which is exactly what marks "first message of a new
    /// chain" to the receiver.
    pub(crate) fn start_sending_chain(&mut self) -> Result<RatchetHeader, RatchetError> {
        let ecdh_shared = aegis_crypto::ecdh::brainpool512_diffie_hellman(
            &self.self_ratchet_ecdh,
            &self.peer_ratchet_ecdh_public,
        )?;
        let (kem_ciphertext_vec, kem_shared) =
            aegis_crypto::kem::ml_kem_encapsulate(&self.peer_ratchet_kem_public)?;
        let kem_ciphertext: [u8; KEM_CIPHERTEXT_LEN] = kem_ciphertext_vec
            .try_into()
            .expect("ml_kem_encapsulate ciphertext is always KEM_CIPHERTEXT_LEN bytes");
        let hybrid_secret = Self::hybrid_ratchet_secret(&ecdh_shared, &kem_shared);

        let (new_root_key, chain_key) = kdf_rk(&self.root_key, hybrid_secret.as_ref());
        self.root_key = new_root_key;
        self.sending_chain = Some(ChainState { chain_key });

        Ok(RatchetHeader {
            ratchet_ecdh_public: self
                .self_ratchet_ecdh
                .public_key_bytes()
                .try_into()
                .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes"),
            ratchet_kem_public: self
                .self_ratchet_kem
                .encapsulation_key_bytes()
                .try_into()
                .expect("encapsulation_key_bytes is always KEM_ENCAPSULATION_KEY_LEN bytes"),
            kem_ciphertext: Some(kem_ciphertext),
            message_number: 0, // caller (encrypt_message, Task 8) fills in the real number
            previous_chain_length: self.previous_chain_length,
        })
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p aegis-ratchet state::`
Expected: all tests (Task 6's 6 plus this task's 2) pass.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-ratchet/src/state.rs
git commit -m "aegis-ratchet: implement the DH ratchet step"
```

---

### Task 8: `encrypt_message`

**Files:**
- Modify: `crates/aegis-ratchet/src/state.rs`
- Modify: `crates/aegis-ratchet/src/lib.rs`

**Interfaces:**
- Consumes: `state::{RatchetState, RatchetMessage}` (Task 6/7), `kdf_chain::kdf_ck` (Task 2), `aegis_crypto::aead::{encrypt, AeadAlgorithm}`.
- Produces: `pub fn encrypt_message(state: &mut RatchetState, plaintext: &[u8], aad: &[u8]) -> Result<RatchetMessage, RatchetError>`, re-exported from `lib.rs`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn encrypt_message_starts_a_sending_chain_on_first_call() {
    let root_key = [0x33u8; ROOT_KEY_LEN];
    let bob_ecdh = Brainpool512SecretKey::generate();
    let bob_kem = MlKem1024KeyPair::generate();
    let mut state = RatchetState::from_x3dh_initiator(
        root_key,
        bob_ecdh.public_key_bytes().try_into().unwrap(),
        bob_kem.encapsulation_key_bytes().try_into().unwrap(),
    );

    assert!(state.sending_chain.is_none());
    let message = state.encrypt(b"hello", b"").unwrap();
    assert!(state.sending_chain.is_some());
    assert!(message.header.kem_ciphertext.is_some());
    assert_eq!(message.header.message_number, 0);
}

#[test]
fn encrypt_message_increments_the_send_counter() {
    let root_key = [0x33u8; ROOT_KEY_LEN];
    let bob_ecdh = Brainpool512SecretKey::generate();
    let bob_kem = MlKem1024KeyPair::generate();
    let mut state = RatchetState::from_x3dh_initiator(
        root_key,
        bob_ecdh.public_key_bytes().try_into().unwrap(),
        bob_kem.encapsulation_key_bytes().try_into().unwrap(),
    );

    let first = state.encrypt(b"one", b"").unwrap();
    let second = state.encrypt(b"two", b"").unwrap();
    assert_eq!(first.header.message_number, 0);
    assert_eq!(second.header.message_number, 1);
    assert!(second.header.kem_ciphertext.is_none(), "same chain, no new ratchet step needed");
    assert_ne!(first.ciphertext, second.ciphertext);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-ratchet encrypt_message_starts_a_sending_chain_on_first_call`
Expected: compile error — `no method named encrypt found for struct RatchetState`.

- [ ] **Step 3: Write minimal implementation**

Append to the `impl RatchetState` block in `crates/aegis-ratchet/src/state.rs`:

```rust
    /// Encrypt `plaintext`, advancing the sending chain by one message
    /// (design §4.1). Starts a fresh sending chain first if none
    /// exists yet (first call ever, or right after a DH ratchet step
    /// populated `receiving_chain` but not `sending_chain`).
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<RatchetMessage, RatchetError> {
        let mut header = match &self.sending_chain {
            Some(_) => RatchetHeader {
                ratchet_ecdh_public: self
                    .self_ratchet_ecdh
                    .public_key_bytes()
                    .try_into()
                    .expect("public_key_bytes is always ECDH_PUBLIC_KEY_LEN bytes"),
                ratchet_kem_public: self
                    .self_ratchet_kem
                    .encapsulation_key_bytes()
                    .try_into()
                    .expect("encapsulation_key_bytes is always KEM_ENCAPSULATION_KEY_LEN bytes"),
                kem_ciphertext: None,
                message_number: 0, // set below
                previous_chain_length: self.previous_chain_length,
            },
            None => self.start_sending_chain()?,
        };

        let chain = self
            .sending_chain
            .as_mut()
            .expect("either the existing branch above or start_sending_chain populated this");
        let (new_chain_key, message_key) = kdf_ck(&chain.chain_key);
        chain.chain_key = new_chain_key;

        header.message_number = self.send_message_number;

        let nonce = [0u8; 12]; // safe: message_key is single-use, see Task 8 notes below
        let ciphertext = aegis_crypto::aead::encrypt(
            aegis_crypto::aead::AeadAlgorithm::Aes256Gcm,
            message_key.as_ref(),
            &nonce,
            aad,
            plaintext,
        )
        .map_err(|_| RatchetError::DecryptionFailed)?; // encrypt only fails on malformed inputs, which don't occur here; kept as a Result for symmetry with decrypt

        self.send_message_number += 1;

        Ok(RatchetMessage { header, ciphertext })
    }
```

**Nonce note**: this uses an all-zero 12-byte nonce, not `aead::ChunkNonceSequence`. That type is built for many chunks under one long-lived key (salt+counter for uniqueness across a sequence); here, every `message_key` is derived fresh per message via `kdf_ck` and used exactly once, so nonce reuse under one key never happens by construction — matching Signal's own Double Ratchet design, where each message key encrypts exactly one message. Document this reasoning at the call site (as above), don't silently reuse `ChunkNonceSequence` for a use case it wasn't designed for.

Add to `crates/aegis-ratchet/src/lib.rs`, re-exporting the type most callers need directly:

```rust
pub use state::{RatchetHeader, RatchetMessage, RatchetState};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p aegis-ratchet state::`
Expected: all tests pass, including this task's 2.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-ratchet/src/
git commit -m "aegis-ratchet: implement encrypt_message"
```

---

### Task 9: `decrypt_message` (in-order case)

**Files:**
- Modify: `crates/aegis-ratchet/src/state.rs`

**Interfaces:**
- Consumes: everything from Task 8, `aegis_crypto::aead::decrypt`.
- Produces: `pub fn RatchetState::decrypt(&mut self, message: &RatchetMessage, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, RatchetError>`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn decrypt_recovers_what_encrypt_produced_across_the_x3dh_handoff() {
    use crate::prekey::{generate_signed_pre_key, IdentityKeyPair, PreKeyBundle};
    use crate::x3dh::{initiate_x3dh, respond_to_x3dh};
    use aegis_crypto::version::ProtocolVersion;

    let alice_identity = IdentityKeyPair::generate();
    let bob_identity = IdentityKeyPair::generate();
    let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob_identity);
    let bundle = PreKeyBundle {
        identity: bob_identity.public_keys(),
        signed_pre_key,
        one_time_pre_key: None,
    };

    let (alice_root_key, preamble, _alice_ephemeral) =
        initiate_x3dh(&alice_identity, &bundle, ProtocolVersion::V1).unwrap();
    let mut alice_state = RatchetState::from_x3dh_initiator(
        *alice_root_key,
        bundle.signed_pre_key.ecdh_public,
        bundle.signed_pre_key.kem_encapsulation_key,
    );

    let bob_root_key =
        respond_to_x3dh(&bob_identity, &bob_spk_ecdh, &bob_spk_kem, None, &preamble).unwrap();
    let mut bob_state = RatchetState::from_x3dh_responder(
        *bob_root_key,
        preamble.alice_ephemeral_ecdh_public,
        bob_spk_ecdh,
        bob_spk_kem,
    );

    let message = alice_state.encrypt(b"hello bob", b"").unwrap();
    let plaintext = bob_state.decrypt(&message, b"").unwrap();
    assert_eq!(&*plaintext, b"hello bob");
}

#[test]
fn decrypt_rejects_tampered_ciphertext_without_panicking() {
    // Set up the same two-party session as above (helper extracted
    // for reuse -- see Step 3 note), then:
    let (mut alice_state, mut bob_state) = two_party_session();
    let mut message = alice_state.encrypt(b"hello bob", b"").unwrap();
    message.ciphertext[0] ^= 0xFF;

    assert_eq!(bob_state.decrypt(&message, b"").unwrap_err(), RatchetError::DecryptionFailed);
}

#[test]
fn decrypt_rejects_wrong_aad_without_panicking() {
    let (mut alice_state, mut bob_state) = two_party_session();
    let message = alice_state.encrypt(b"hello bob", b"correct-aad").unwrap();
    assert_eq!(
        bob_state.decrypt(&message, b"wrong-aad").unwrap_err(),
        RatchetError::DecryptionFailed,
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-ratchet decrypt_recovers_what_encrypt_produced_across_the_x3dh_handoff`
Expected: compile error — `no method named decrypt found for struct RatchetState` / `cannot find function two_party_session`.

- [ ] **Step 3: Write minimal implementation**

Add the `two_party_session` test helper (used by this task and Task 10/11) near the top of `state.rs`'s `#[cfg(test)] mod tests`:

```rust
fn two_party_session() -> (RatchetState, RatchetState) {
    use crate::prekey::{generate_signed_pre_key, IdentityKeyPair, PreKeyBundle};
    use crate::x3dh::{initiate_x3dh, respond_to_x3dh};
    use aegis_crypto::version::ProtocolVersion;

    let alice_identity = IdentityKeyPair::generate();
    let bob_identity = IdentityKeyPair::generate();
    let (signed_pre_key, bob_spk_ecdh, bob_spk_kem) = generate_signed_pre_key(&bob_identity);
    let bundle = PreKeyBundle {
        identity: bob_identity.public_keys(),
        signed_pre_key,
        one_time_pre_key: None,
    };

    let (alice_root_key, preamble, _) = initiate_x3dh(&alice_identity, &bundle, ProtocolVersion::V1).unwrap();
    let alice_state = RatchetState::from_x3dh_initiator(
        *alice_root_key,
        bundle.signed_pre_key.ecdh_public,
        bundle.signed_pre_key.kem_encapsulation_key,
    );

    let bob_root_key =
        respond_to_x3dh(&bob_identity, &bob_spk_ecdh, &bob_spk_kem, None, &preamble).unwrap();
    let bob_state = RatchetState::from_x3dh_responder(
        *bob_root_key,
        preamble.alice_ephemeral_ecdh_public,
        bob_spk_ecdh,
        bob_spk_kem,
    );

    (alice_state, bob_state)
}
```

Append to the `impl RatchetState` block:

```rust
    /// Decrypt and authenticate `message` (design §4.2 in-order case;
    /// Task 10 adds out-of-order/skipped-key handling on top of this).
    /// Performs a DH ratchet step first if `message.header` carries a
    /// peer ratchet public key not yet seen.
    pub fn decrypt(&mut self, message: &RatchetMessage, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, RatchetError> {
        if message.header.ratchet_ecdh_public != self.peer_ratchet_ecdh_public
            || self.receiving_chain.is_none()
        {
            self.dh_ratchet_step(&message.header)?;
        }

        let chain = self
            .receiving_chain
            .as_mut()
            .ok_or(RatchetError::UnknownMessage)?; // dh_ratchet_step above always populates this when it runs; None here means a header we can't process

        if message.header.message_number != self.receive_message_number {
            // Task 10 handles this case (skipped-key cache); for now,
            // an out-of-order message is an error rather than silently
            // mishandled.
            return Err(RatchetError::UnknownMessage);
        }

        let (new_chain_key, message_key) = kdf_ck(&chain.chain_key);
        chain.chain_key = new_chain_key;

        let nonce = [0u8; 12]; // matches encrypt_message's nonce construction -- see Task 8 notes
        let plaintext = aegis_crypto::aead::decrypt(
            aegis_crypto::aead::AeadAlgorithm::Aes256Gcm,
            message_key.as_ref(),
            &nonce,
            aad,
            &message.ciphertext,
        )
        .map_err(|_| RatchetError::DecryptionFailed)?;

        self.receive_message_number += 1;

        Ok(Zeroizing::new(plaintext))
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p aegis-ratchet state::`
Expected: all tests pass, including this task's 3.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-ratchet/src/state.rs
git commit -m "aegis-ratchet: implement decrypt_message (in-order case)"
```

---

### Task 10: Skipped-message key cache + out-of-order decryption

**Files:**
- Create: `crates/aegis-ratchet/src/skipped_keys.rs`
- Modify: `crates/aegis-ratchet/src/state.rs`
- Modify: `crates/aegis-ratchet/src/lib.rs`

**Interfaces:**
- Consumes: `kdf_chain::{kdf_ck, MESSAGE_KEY_LEN}` (Task 2), `prekey::ECDH_PUBLIC_KEY_LEN` (Task 3).
- Produces: `pub(crate) struct SkippedKeyCache` with `MAX_SKIP: usize = 1000`, `.insert(sender_ratchet_ecdh_public, message_number, key)`, `.take(sender_ratchet_ecdh_public, message_number) -> Option<Zeroizing<[u8; MESSAGE_KEY_LEN]>>`, `.len()`. Adds `skipped_message_keys: SkippedKeyCache` field to `RatchetState` and wires it into `decrypt` (Task 9).

- [ ] **Step 1: Write the failing test**

`crates/aegis-ratchet/src/skipped_keys.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_take_returns_the_key() {
        let mut cache = SkippedKeyCache::new();
        let sender = [0x01u8; 129];
        cache.insert(sender, 3, [0xAAu8; 32].into());
        let key = cache.take(sender, 3).unwrap();
        assert_eq!(*key, [0xAAu8; 32]);
    }

    #[test]
    fn take_consumes_the_entry() {
        let mut cache = SkippedKeyCache::new();
        let sender = [0x01u8; 129];
        cache.insert(sender, 3, [0xAAu8; 32].into());
        assert!(cache.take(sender, 3).is_some());
        assert!(cache.take(sender, 3).is_none(), "a matched key must be single-use");
    }

    #[test]
    fn take_misses_for_an_unknown_key() {
        let mut cache = SkippedKeyCache::new();
        assert!(cache.take([0x01u8; 129], 0).is_none());
    }

    #[test]
    fn different_senders_with_the_same_message_number_are_distinct() {
        let mut cache = SkippedKeyCache::new();
        let sender_a = [0x01u8; 129];
        let sender_b = [0x02u8; 129];
        cache.insert(sender_a, 0, [0xAAu8; 32].into());
        cache.insert(sender_b, 0, [0xBBu8; 32].into());
        assert_eq!(*cache.take(sender_a, 0).unwrap(), [0xAAu8; 32]);
        assert_eq!(*cache.take(sender_b, 0).unwrap(), [0xBBu8; 32]);
    }

    #[test]
    fn insertion_past_the_bound_evicts_the_oldest_entry() {
        let mut cache = SkippedKeyCache::new();
        let sender = [0x01u8; 129];
        for n in 0..MAX_SKIP as u32 {
            cache.insert(sender, n, [n as u8; 32].into());
        }
        assert_eq!(cache.len(), MAX_SKIP);

        cache.insert(sender, MAX_SKIP as u32, [0xFFu8; 32].into());
        assert_eq!(cache.len(), MAX_SKIP, "must stay at the bound, not grow past it");
        assert!(cache.take(sender, 0).is_none(), "oldest entry (message 0) must have been evicted");
        assert!(cache.take(sender, MAX_SKIP as u32).is_some(), "newest entry must still be present");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-ratchet skipped_keys::`
Expected: compile error — `cannot find struct SkippedKeyCache`.

- [ ] **Step 3: Write minimal implementation**

```rust
//! Bounded cache of skipped-message keys, so a message that arrives
//! out of order still decrypts (design §5). Adopts Signal's algorithm
//! directly: keyed by `(sender_ratchet_ecdh_public, message_number)`,
//! bounded to `MAX_SKIP` entries (Signal's own default), FIFO eviction
//! past the bound, single-use (a lookup that hits removes the entry).

use crate::kdf_chain::MESSAGE_KEY_LEN;
use crate::prekey::ECDH_PUBLIC_KEY_LEN;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Signal's own reference `MAX_SKIP` default
/// (<https://signal.org/docs/specifications/doubleratchet/#deferring-key-derivation>).
pub const MAX_SKIP: usize = 1000;

type CacheKey = ([u8; ECDH_PUBLIC_KEY_LEN], u32);

pub(crate) struct SkippedKeyCache {
    // `insertion_order` tracks FIFO eviction order; `entries` is the
    // actual lookup table. A `HashMap` alone has no defined iteration
    // order to evict by, hence the parallel `Vec`.
    entries: HashMap<CacheKey, Zeroizing<[u8; MESSAGE_KEY_LEN]>>,
    insertion_order: std::collections::VecDeque<CacheKey>,
}

impl SkippedKeyCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: std::collections::VecDeque::new(),
        }
    }

    pub(crate) fn insert(
        &mut self,
        sender_ratchet_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
        message_number: u32,
        key: Zeroizing<[u8; MESSAGE_KEY_LEN]>,
    ) {
        let cache_key = (sender_ratchet_ecdh_public, message_number);
        if self.entries.insert(cache_key, key).is_none() {
            self.insertion_order.push_back(cache_key);
        }
        while self.insertion_order.len() > MAX_SKIP {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    pub(crate) fn take(
        &mut self,
        sender_ratchet_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
        message_number: u32,
    ) -> Option<Zeroizing<[u8; MESSAGE_KEY_LEN]>> {
        let cache_key = (sender_ratchet_ecdh_public, message_number);
        let key = self.entries.remove(&cache_key)?;
        self.insertion_order.retain(|k| k != &cache_key);
        Some(key)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}
```

Add `mod skipped_keys;` (crate-private — this type is never part of the public API) to `crates/aegis-ratchet/src/lib.rs`.

Now wire it into `RatchetState` and `decrypt` (`state.rs`):

Add the field to the `RatchetState` struct definition (Task 6):

```rust
    pub(crate) skipped_message_keys: crate::skipped_keys::SkippedKeyCache,
```

Initialize it (`crate::skipped_keys::SkippedKeyCache::new()`) in both `from_x3dh_initiator` and `from_x3dh_responder`.

Replace `dh_ratchet_step`'s body (Task 7) to derive-and-cache the old receiving chain's remaining keys **before** overwriting it — insert this at the very top of the function, before the existing `let kem_ciphertext = ...` line:

```rust
        if let Some(old_chain) = &mut self.receiving_chain {
            let mut chain_key = old_chain.chain_key.clone();
            while self.receive_message_number < header.previous_chain_length {
                let (new_chain_key, message_key) = kdf_ck(&chain_key);
                self.skipped_message_keys.insert(
                    self.peer_ratchet_ecdh_public,
                    self.receive_message_number,
                    message_key,
                );
                chain_key = new_chain_key;
                self.receive_message_number += 1;
            }
        }
```

(`ChainState.chain_key` needs `#[derive(Clone)]`-equivalent support — `Zeroizing<[u8; N]>` already implements `Clone` since `[u8; N]` does, so `old_chain.chain_key.clone()` works without further changes.)

Replace `decrypt`'s message-number check (Task 9) — the block that currently returns `Err(RatchetError::UnknownMessage)` for any out-of-order message — with:

```rust
        if message.header.message_number < self.receive_message_number {
            let key = self
                .skipped_message_keys
                .take(self.peer_ratchet_ecdh_public, message.header.message_number)
                .ok_or(RatchetError::UnknownMessage)?;
            let nonce = [0u8; 12];
            let plaintext = aegis_crypto::aead::decrypt(
                aegis_crypto::aead::AeadAlgorithm::Aes256Gcm,
                key.as_ref(),
                &nonce,
                aad,
                &message.ciphertext,
            )
            .map_err(|_| RatchetError::DecryptionFailed)?;
            return Ok(Zeroizing::new(plaintext));
        }

        if message.header.message_number > self.receive_message_number {
            let gap = message.header.message_number - self.receive_message_number;
            if gap as usize > crate::skipped_keys::MAX_SKIP {
                return Err(RatchetError::SkippedKeyLimitExceeded);
            }
            while self.receive_message_number < message.header.message_number {
                let (new_chain_key, message_key) = kdf_ck(&chain.chain_key);
                chain.chain_key = new_chain_key;
                self.skipped_message_keys.insert(
                    self.peer_ratchet_ecdh_public,
                    self.receive_message_number,
                    message_key,
                );
                self.receive_message_number += 1;
            }
        }
```

...inserted immediately after the `let chain = self.receiving_chain.as_mut()...` line and before the existing in-order decrypt path (which now only runs for the exact `message_number == receive_message_number` case — the two blocks above return early for `<` and fast-forward in place for `>`).

- [ ] **Step 4: Write the out-of-order/eviction tests, then verify all pass**

Add to `state.rs`'s test module:

```rust
#[test]
fn out_of_order_message_still_decrypts() {
    let (mut alice_state, mut bob_state) = two_party_session();
    let first = alice_state.encrypt(b"one", b"").unwrap();
    let second = alice_state.encrypt(b"two", b"").unwrap();

    // Bob receives "two" before "one".
    let plaintext_two = bob_state.decrypt(&second, b"").unwrap();
    assert_eq!(&*plaintext_two, b"two");
    let plaintext_one = bob_state.decrypt(&first, b"").unwrap();
    assert_eq!(&*plaintext_one, b"one");
}

#[test]
fn a_message_delivered_twice_fails_the_second_time() {
    let (mut alice_state, mut bob_state) = two_party_session();
    let message = alice_state.encrypt(b"one", b"").unwrap();
    assert!(bob_state.decrypt(&message, b"").is_ok());
    assert_eq!(bob_state.decrypt(&message, b"").unwrap_err(), RatchetError::UnknownMessage);
}

#[test]
fn skip_gap_larger_than_max_skip_is_rejected() {
    let (mut alice_state, mut bob_state) = two_party_session();
    for _ in 0..=crate::skipped_keys::MAX_SKIP {
        alice_state.encrypt(b"filler", b"").unwrap();
    }
    let far_future = alice_state.encrypt(b"too far", b"").unwrap();
    assert_eq!(
        bob_state.decrypt(&far_future, b"").unwrap_err(),
        RatchetError::SkippedKeyLimitExceeded,
    );
}
```

Run: `cargo test -p aegis-ratchet`
Expected: every test in the crate passes.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-ratchet/src/
git commit -m "aegis-ratchet: add bounded skipped-message-key cache, out-of-order decrypt"
```

---

### Task 11: End-to-end multi-message conversation scenarios

**Files:**
- Modify: `crates/aegis-ratchet/src/state.rs` (or create `crates/aegis-ratchet/tests/conversation.rs` as an integration test — either is fine; an integration test file better matches this task's "black-box, from outside the crate" spirit, so prefer that if the executor has a preference, otherwise the inline `mod tests` is equally valid).

**Interfaces:**
- Consumes: the full public API (`RatchetState`, `encrypt`/`decrypt`, `x3dh::{initiate_x3dh, respond_to_x3dh}`, `prekey::*`).
- Produces: no new production code — this task is pure verification that the pieces built in Tasks 1-10 compose correctly under realistic multi-message, bidirectional, reordered traffic.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn a_realistic_bidirectional_conversation_with_reordering_and_ratcheting() {
    let (mut alice_state, mut bob_state) = two_party_session();

    // Alice sends three messages on her first chain.
    let a1 = alice_state.encrypt(b"hi bob", b"").unwrap();
    let a2 = alice_state.encrypt(b"how are you", b"").unwrap();
    let a3 = alice_state.encrypt(b"?", b"").unwrap();

    // Bob receives them out of order: a2, a1, a3.
    assert_eq!(&*bob_state.decrypt(&a2, b"").unwrap(), b"how are you");
    assert_eq!(&*bob_state.decrypt(&a1, b"").unwrap(), b"hi bob");
    assert_eq!(&*bob_state.decrypt(&a3, b"").unwrap(), b"?");

    // Bob replies -- this is his first send, so it's a DH ratchet step.
    let b1 = bob_state.encrypt(b"good, you?", b"").unwrap();
    assert!(b1.header.kem_ciphertext.is_some());
    assert_eq!(&*alice_state.decrypt(&b1, b"").unwrap(), b"good, you?");

    // Alice replies -- another DH ratchet step, since Bob's message
    // carried a ratchet key Alice hadn't seen.
    let a4 = alice_state.encrypt(b"great!", b"").unwrap();
    assert!(a4.header.kem_ciphertext.is_some());
    assert_eq!(&*bob_state.decrypt(&a4, b"").unwrap(), b"great!");

    // A longer run after ratcheting, still in order, to confirm the
    // chain continues to advance correctly post-ratchet.
    for i in 0..10u32 {
        let msg = alice_state.encrypt(format!("message {i}").as_bytes(), b"").unwrap();
        let plaintext = bob_state.decrypt(&msg, b"").unwrap();
        assert_eq!(plaintext.as_slice(), format!("message {i}").as_bytes());
    }
}

#[test]
fn a_long_gap_then_catch_up_derives_every_intervening_key() {
    let (mut alice_state, mut bob_state) = two_party_session();
    let mut messages = Vec::new();
    for i in 0..50u32 {
        messages.push(alice_state.encrypt(format!("msg {i}").as_bytes(), b"").unwrap());
    }

    // Bob only ever sees the last one first.
    let plaintext = bob_state.decrypt(&messages[49], b"").unwrap();
    assert_eq!(plaintext.as_slice(), b"msg 49");

    // Then catches up on all the earlier ones, in reverse order.
    for i in (0..49u32).rev() {
        let plaintext = bob_state.decrypt(&messages[i as usize], b"").unwrap();
        assert_eq!(plaintext.as_slice(), format!("msg {i}").as_bytes());
    }
}

#[test]
fn malformed_wire_bytes_are_rejected_at_every_public_entry_point_without_panicking() {
    use crate::prekey::PreKeyBundle;
    use crate::state::{RatchetMessage, RatchetState};

    for len in [0, 1, 10, 500] {
        let junk = vec![0xAAu8; len];
        assert!(PreKeyBundle::from_bytes(&junk).is_err());
        assert!(RatchetMessage::from_bytes(&junk).is_err());
        assert!(RatchetState::from_bytes(&junk).is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

These exercise only already-implemented functions, so this step is a slightly different shape than earlier tasks: it should **compile** immediately (everything it calls exists after Task 10) but the first two tests are expected to **fail on an assertion**, not a compile error, if any earlier task has a subtle bug — that's what this task is for. Run:

`cargo test -p aegis-ratchet a_realistic_bidirectional_conversation_with_reordering_and_ratcheting`

Expected on a correct implementation: pass immediately. If it fails, the failure is real — debug the specific assertion that fired (which chain/message-number/ratchet-state invariant broke) rather than adjusting the test to match broken behavior.

- [ ] **Step 3–4: N/A — no new implementation code**

If Step 2 fails, fix the bug in whichever earlier task's code caused it, following that task's own TDD cycle for the fix (write a smaller failing test isolating the specific broken behavior first, in that task's module, then fix it there) — don't patch the state machine from inside this task's test file.

- [ ] **Step 5: Run the full crate test suite one more time**

Run: `cargo test -p aegis-ratchet`
Expected: every test across all 11 tasks passes, zero warnings (`cargo clippy -p aegis-ratchet -- -D warnings` should also be clean, matching `aegis-crypto`'s standard).

- [ ] **Step 6: Commit**

```bash
git add crates/aegis-ratchet/
git commit -m "aegis-ratchet: end-to-end conversation tests (reordering, ratcheting, long gaps)"
```

---

## Self-Review Notes (for whoever executes this plan)

- **Task 6's serialization gap is resolved**: extend `aegis-crypto` with additive export methods (Steps 3a-3c), not seed-based reconstruction duplicated inside `aegis-ratchet` — decided by your human partner, concrete code included inline in that task.
- **Spec coverage**: design §2 (X3DH) → Tasks 3-5; §3 items 1-3 (ratchet, KDF chains, PCS via zeroization) → Tasks 2, 6-9; §4.1-4.2 (encrypt/decrypt) → Tasks 8-9; §4.3 (wire format) → Task 6; §5 (skipped-key cache) → Task 10; §6 (error handling) → Task 1, threaded through every task; §7 (testing strategy) → Task 11 plus the per-task unit tests throughout. No section of the approved design is without a task.
- **Type consistency checked**: `RatchetState`/`RatchetHeader`/`RatchetMessage` field names and the `encrypt`/`decrypt` method signatures are identical everywhere they're used across Tasks 6-11 (verified while writing, not left to a final pass) — in particular, `previous_chain_length` flows from `dh_ratchet_step` through to the header `start_sending_chain`/`encrypt` produce, exactly as design §3.2/§4.3 specify.
