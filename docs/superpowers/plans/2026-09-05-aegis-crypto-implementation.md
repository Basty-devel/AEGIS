# aegis-crypto Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the `aegis-crypto` crate — the hybrid post-quantum cryptographic primitives (KEM, signatures, AEAD, KDFs, SAS) that every other AegisPQC crate depends on.

**Architecture:** One small, focused module per primitive family (`kdf`, `aead`, `passphrase`, `sas`, `signature`, `kem`, `ecdh`, `hybrid`, `version`), each wrapping exactly one audited upstream crate behind a narrow AegisPQC-specific API. No module invents cryptographic math; every construction cites its published reference in a doc comment, per spec §9.1.

**Tech Stack:** Rust (workspace already scaffolded, MSVC toolchain confirmed working), RustCrypto crates for all primitives except brainpoolP512r1 (see Task 8).

**Spec:** [`AEGIS.Plan.V0.2.md`](../../../AEGIS.Plan.V0.2.md) Section 2 (Cryptographic Architecture) and Section 9.1 (Cryptographic Implementation Ground Rules).

## Global Constraints

- `#![deny(unsafe_code)]` is already set at the workspace root (`Cargo.toml`). `aegis-crypto` adds no exception — every dependency used here is pure safe Rust (verified below), consistent with spec §10.
- Argon2id production parameters are fixed by spec §2: Memory = 64 MiB, Iterations = 4, Parallelism = 4. Test-only parameters (Task 4) differ — see that task.
- AEAD nonces are constructed as 32-bit random salt ‖ 64-bit big-endian counter (spec §2), never derived from wall-clock time.
- Every HKDF-SHA512 call's `info` parameter MUST include a domain-separation label, the protocol version byte, and both parties' public keys (spec §2) — this is enforced by `kdf::derive_key`'s signature (Task 2), which has no way to omit them.
- Every construction's doc comment MUST cite its published reference (spec §9.1) — this is checked per-task below, not left to a final pass.
- `aegis-crypto`'s crate-level docs and `SECURITY_DISCLAIMER` constant (Task 1) carry the mandatory "not independently audited" notice from the spec's document header — this must ship from the very first commit, not be added later.
- These are pre-1.0 crates with real API churn between minor versions. If a step's exact method or type name has moved since this plan was written, run `cargo doc --open -p <crate>` to find the current name — that is the TDD "verify RED" step doing its job (a compile error telling you a symbol doesn't exist), not a sign the plan or design is wrong.
- **Licensing note (not a task, just visibility):** `bp512-nestler` (Task 8) is licensed PolyForm-Noncommercial-1.0.0, not an OSI open-source license. `AEGIS`'s own workspace `Cargo.toml` deliberately has no `license` field yet (an earlier decision, not an oversight). Whatever license AEGIS eventually adopts, it needs to be compatible with a noncommercial-only dependency, or Task 8's dependency needs revisiting first.

---

### Task 1: Foundational dependencies and security disclaimer

**Files:**
- Modify: `crates/aegis-crypto/Cargo.toml`
- Modify: `crates/aegis-crypto/src/lib.rs`
- Test: `crates/aegis-crypto/src/lib.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `aegis_crypto::SECURITY_DISCLAIMER: &'static str`

- [ ] **Step 1: Write the failing test**

In `crates/aegis-crypto/src/lib.rs`, append:

```rust
#[cfg(test)]
mod tests {
    use super::SECURITY_DISCLAIMER;

    #[test]
    fn disclaimer_states_not_audited() {
        assert!(SECURITY_DISCLAIMER.contains("NOT independently audited"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p aegis-crypto disclaimer_states_not_audited`
Expected: compile error — `cannot find value SECURITY_DISCLAIMER in crate aegis_crypto` (the symbol doesn't exist yet; this is the correct RED state for a new item in a compiled language).

- [ ] **Step 3: Add dependencies**

Run these from the repo root (`C:\AEGIS`) so they land in `crates/aegis-crypto/Cargo.toml`:

```bash
cargo add zeroize --features derive -p aegis-crypto
cargo add blake3 -p aegis-crypto
cargo add subtle -p aegis-crypto
cargo add hkdf -p aegis-crypto
cargo add sha2 -p aegis-crypto
cargo add aes-gcm -p aegis-crypto
cargo add chacha20poly1305 -p aegis-crypto
cargo add argon2 -p aegis-crypto
cargo add ed25519-dalek --features rand_core -p aegis-crypto
cargo add ml-dsa -p aegis-crypto
cargo add ml-kem -p aegis-crypto
cargo add elliptic-curve --features ecdh -p aegis-crypto
cargo add getrandom -p aegis-crypto
cargo add signature -p aegis-crypto
cargo add serde --features derive --dev -p aegis-crypto
cargo add serde_json --dev -p aegis-crypto
cargo add hex --dev -p aegis-crypto
```

(`bp512-nestler` is added in Task 8, since it needs the vendor patch set up first.)

- [ ] **Step 4: Write minimal implementation**

Replace the placeholder doc comment in `crates/aegis-crypto/src/lib.rs` with:

```rust
//! Hybrid cryptographic primitives: ML-KEM-1024 + brainpool512r1 KEM
//! combiner, ML-DSA-87 + Ed25519 signatures, AEAD, Argon2id, HKDF-SHA512,
//! and memory zeroization.
//!
//! See `AEGIS.Plan.V0.2.md` Sections 2 and 9.1 (cryptographic ground
//! rules — no construction here may deviate from a cited published
//! reference).

/// AegisPQC cryptographic primitives are NOT independently audited.
/// Do not rely on this code for life-critical communications until a
/// third-party cryptographic audit has been completed. See
/// `AEGIS.Plan.V0.2.md`, document header, and Section 9.1.
pub const SECURITY_DISCLAIMER: &str =
    "AegisPQC cryptographic primitives are NOT independently audited. \
     Do not rely on this code for life-critical communications until a \
     third-party cryptographic audit has been completed.";

pub mod aead;
pub mod ecdh;
pub mod hybrid;
pub mod kdf;
pub mod kem;
pub mod passphrase;
pub mod sas;
pub mod signature;
pub mod version;
```

- [ ] **Step 5: Create empty module files so the crate compiles**

Create each of these with just a doc comment (one line each), matching the descriptions already used in the scaffolding commit:

- `crates/aegis-crypto/src/aead.rs`: `//! AES-256-GCM / ChaCha20-Poly1305 wrapper with mandated nonce construction. See AEGIS.Plan.V0.2.md Section 2.`
- `crates/aegis-crypto/src/ecdh.rs`: `//! brainpoolP512r1 ECDH. See AEGIS.Plan.V0.2.md Section 2.`
- `crates/aegis-crypto/src/hybrid.rs`: `//! Hybrid ML-KEM-1024 + brainpool512r1 KEM combiner. See AEGIS.Plan.V0.2.md Section 2.`
- `crates/aegis-crypto/src/kdf.rs`: `//! Domain-separated HKDF-SHA512. See AEGIS.Plan.V0.2.md Section 2.`
- `crates/aegis-crypto/src/kem.rs`: `//! ML-KEM-1024 wrapper (NIST FIPS 203). See AEGIS.Plan.V0.2.md Section 2.`
- `crates/aegis-crypto/src/passphrase.rs`: `//! Argon2id passphrase KDF. See AEGIS.Plan.V0.2.md Section 2.`
- `crates/aegis-crypto/src/sas.rs`: `//! BLAKE3-based Short Authentication Strings. See AEGIS.Plan.V0.2.md Section 2.`
- `crates/aegis-crypto/src/signature.rs`: `//! Ed25519 + ML-DSA-87 dual-signature wrapper (NIST FIPS 204). See AEGIS.Plan.V0.2.md Section 2.`
- `crates/aegis-crypto/src/version.rs`: `//! Protocol version and algorithm-suite negotiation table. See AEGIS.Plan.V0.2.md Section 2.`

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test -p aegis-crypto disclaimer_states_not_audited`
Expected: `test tests::disclaimer_states_not_audited ... ok`

- [ ] **Step 7: Commit**

```bash
git add crates/aegis-crypto/Cargo.toml crates/aegis-crypto/src/
git commit -m "aegis-crypto: add primitive dependencies and security disclaimer"
```

---

### Task 2: Domain-separated HKDF-SHA512 KDF

**Files:**
- Modify: `crates/aegis-crypto/src/kdf.rs`

**Interfaces:**
- Produces: `pub fn derive_key(ikm: &[u8], domain_label: &[u8], protocol_version: u8, pubkey_a: &[u8], pubkey_b: &[u8], output: &mut [u8]) -> Result<(), hkdf::InvalidLength>`
- Consumes: nothing from earlier tasks.

This implements spec §2's mandatory combiner binding: `info = domain_label || protocol_version || pubkey_A || pubkey_B`. Reference: NIST SP 800-56C (concatenation KDF construction) and RFC 5869 (HKDF).

- [ ] **Step 1: Write the failing tests**

Append to `crates/aegis-crypto/src/kdf.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::derive_key;

    #[test]
    fn same_inputs_are_deterministic() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"label", 1, b"pubkey-a", b"pubkey-b", &mut out1).unwrap();
        derive_key(b"ikm", b"label", 1, b"pubkey-a", b"pubkey-b", &mut out2).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn different_domain_labels_produce_different_output() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"label-a", 1, b"pubkey-a", b"pubkey-b", &mut out1).unwrap();
        derive_key(b"ikm", b"label-b", 1, b"pubkey-a", b"pubkey-b", &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn different_protocol_versions_produce_different_output() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"label", 1, b"pubkey-a", b"pubkey-b", &mut out1).unwrap();
        derive_key(b"ikm", b"label", 2, b"pubkey-a", b"pubkey-b", &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn different_pubkeys_produce_different_output() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_key(b"ikm", b"label", 1, b"pubkey-a", b"pubkey-b", &mut out1).unwrap();
        derive_key(b"ikm", b"label", 1, b"pubkey-x", b"pubkey-y", &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn fills_requested_output_length() {
        let mut out = [0u8; 64];
        derive_key(b"ikm", b"label", 1, b"a", b"b", &mut out).unwrap();
        assert!(out.iter().any(|&b| b != 0));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p aegis-crypto kdf::tests`
Expected: compile error — `cannot find function derive_key in module aegis_crypto::kdf`.

- [ ] **Step 3: Write minimal implementation**

Replace `crates/aegis-crypto/src/kdf.rs`'s contents (keep the existing doc comment at the top):

```rust
//! Domain-separated HKDF-SHA512. See AEGIS.Plan.V0.2.md Section 2.
//!
//! Construction: `K = HKDF-SHA512(salt=None, IKM, info)` where
//! `info = domain_label || protocol_version || pubkey_A || pubkey_B`.
//! Reference: NIST SP 800-56C (concatenation KDF) and RFC 5869 (HKDF).
//! The domain-separation label and public-key transcript binding in
//! `info` are mandatory per spec Section 2 — this function's signature
//! has no way to omit them.

use hkdf::Hkdf;
use sha2::Sha512;

/// Derive `output.len()` bytes of key material from `ikm`, bound to a
/// domain label, protocol version, and both parties' public keys.
pub fn derive_key(
    ikm: &[u8],
    domain_label: &[u8],
    protocol_version: u8,
    pubkey_a: &[u8],
    pubkey_b: &[u8],
    output: &mut [u8],
) -> Result<(), hkdf::InvalidLength> {
    let mut info = Vec::with_capacity(domain_label.len() + 1 + pubkey_a.len() + pubkey_b.len());
    info.extend_from_slice(domain_label);
    info.push(protocol_version);
    info.extend_from_slice(pubkey_a);
    info.extend_from_slice(pubkey_b);

    let hk = Hkdf::<Sha512>::new(None, ikm);
    hk.expand(&info, output)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p aegis-crypto kdf::tests`
Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-crypto/src/kdf.rs
git commit -m "aegis-crypto: domain-separated HKDF-SHA512 KDF"
```

---

### Task 3: AEAD wrapper with mandated nonce construction

**Files:**
- Modify: `crates/aegis-crypto/src/aead.rs`

**Interfaces:**
- Produces:
  - `pub struct ChunkNonceSequence` with `pub fn new(salt: [u8; 4]) -> Self` and `pub fn next(&mut self) -> [u8; 12]`
  - `pub enum AeadAlgorithm { Aes256Gcm, ChaCha20Poly1305 }`
  - `pub fn encrypt(alg: AeadAlgorithm, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, aead::Error>`
  - `pub fn decrypt(alg: AeadAlgorithm, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error>`
- Consumes: nothing from earlier tasks.

Nonce construction (spec §2): 32-bit random salt (generated once per session/file) ‖ 64-bit big-endian monotonic counter — unique by construction even under key reuse.

- [ ] **Step 1: Write the failing tests**

Append to `crates/aegis-crypto/src/aead.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn nonce_sequence_is_unique_across_many_calls() {
        let mut seq = ChunkNonceSequence::new([0xAA, 0xBB, 0xCC, 0xDD]);
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(seq.next()));
        }
    }

    #[test]
    fn nonce_sequence_embeds_salt_and_increments_counter() {
        let mut seq = ChunkNonceSequence::new([1, 2, 3, 4]);
        let n0 = seq.next();
        let n1 = seq.next();
        assert_eq!(&n0[..4], &[1, 2, 3, 4]);
        assert_eq!(&n1[..4], &[1, 2, 3, 4]);
        assert_eq!(&n0[4..], &0u64.to_be_bytes());
        assert_eq!(&n1[4..], &1u64.to_be_bytes());
    }

    #[test]
    fn aes256gcm_round_trips() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let ct = encrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"aad", b"hello aegis").unwrap();
        let pt = decrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello aegis");
    }

    #[test]
    fn chacha20poly1305_round_trips() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let ct = encrypt(AeadAlgorithm::ChaCha20Poly1305, &key, &nonce, b"aad", b"hello aegis").unwrap();
        let pt = decrypt(AeadAlgorithm::ChaCha20Poly1305, &key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello aegis");
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let mut ct = encrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"aad", b"hello aegis").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(decrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"aad", &ct).is_err());
    }

    /// NIST CAVS vector from `gcmEncryptExtIV256.rsp`, first empty-plaintext
    /// entry, as vendored in the `aes-gcm` crate's own test suite
    /// (RustCrypto/AEADs, aes-gcm/tests/aes256gcm.rs). Verifies our wrapper's
    /// plumbing against an official KAT per spec Section 9.1.
    #[test]
    fn aes256gcm_official_kat_empty_plaintext() {
        let key: [u8; 32] =
            hex::decode("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4")
                .unwrap()[..32]
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = hex::decode("516c33929df5a3284ff463d7").unwrap()[..12]
            .try_into()
            .unwrap();
        let expected_tag = hex::decode("bdc1ac884d332457a1d2664f168c76f0").unwrap();

        let ct = encrypt(AeadAlgorithm::Aes256Gcm, &key, &nonce, b"", b"").unwrap();
        assert_eq!(ct, expected_tag, "ciphertext for empty plaintext is just the 16-byte tag");
    }

    /// RFC 8439 Section 2.8.2 worked example — the canonical
    /// ChaCha20-Poly1305 AEAD test vector, transcribed directly from the
    /// RFC text. Verifies our wrapper's plumbing against an official KAT
    /// per spec Section 9.1.
    #[test]
    fn chacha20poly1305_official_kat_rfc8439() {
        let key: [u8; 32] = hex::decode(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )
        .unwrap()[..32]
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex::decode("070000004041424344454647").unwrap()[..12]
            .try_into()
            .unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ciphertext_and_tag = hex::decode(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2",
            "a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b",
            "1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58",
            "fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b",
            "6116",
            "1ae10b594f09e26a7e902ecbd0600691",
        ))
        .unwrap();

        let ct = encrypt(
            AeadAlgorithm::ChaCha20Poly1305,
            &key,
            &nonce,
            &aad,
            plaintext,
        )
        .unwrap();
        assert_eq!(ct, expected_ciphertext_and_tag);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p aegis-crypto aead::tests`
Expected: compile errors — `ChunkNonceSequence`, `AeadAlgorithm`, `encrypt`, `decrypt` don't exist yet.

- [ ] **Step 3: Write minimal implementation**

Replace `crates/aegis-crypto/src/aead.rs`'s contents (keep the existing doc comment):

```rust
//! AES-256-GCM / ChaCha20-Poly1305 wrapper with mandated nonce
//! construction. See AEGIS.Plan.V0.2.md Section 2.
//!
//! Nonce construction: 32-bit random salt (generated once per
//! session/file) concatenated with a 64-bit big-endian monotonic
//! counter — unique by construction even under key reuse.

use aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;

/// Produces unique 96-bit nonces for a single session or file key:
/// a fixed 32-bit random salt followed by a 64-bit big-endian counter.
pub struct ChunkNonceSequence {
    salt: [u8; 4],
    counter: u64,
}

impl ChunkNonceSequence {
    pub fn new(salt: [u8; 4]) -> Self {
        Self { salt, counter: 0 }
    }

    /// Returns the next nonce in the sequence. Panics on counter
    /// overflow (2^64 chunks under one key is not a realistic limit
    /// for this protocol's message/file sizes).
    pub fn next(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self
            .counter
            .checked_add(1)
            .expect("nonce counter exhausted");
        nonce
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub fn encrypt(
    alg: AeadAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, aead::Error> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match alg {
        AeadAlgorithm::Aes256Gcm => {
            Aes256Gcm::new(key.into()).encrypt(nonce.into(), payload)
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            ChaCha20Poly1305::new(key.into()).encrypt(nonce.into(), payload)
        }
    }
}

pub fn decrypt(
    alg: AeadAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, aead::Error> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match alg {
        AeadAlgorithm::Aes256Gcm => {
            Aes256Gcm::new(key.into()).decrypt(nonce.into(), payload)
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            ChaCha20Poly1305::new(key.into()).decrypt(nonce.into(), payload)
        }
    }
}
```

Add the `aead` crate (the trait crate, separate from `aes-gcm`/`chacha20poly1305` which re-export it, but we reference `aead::Error`/`aead::Payload` directly):

```bash
cargo add aead -p aegis-crypto
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p aegis-crypto aead::tests`
Expected: all 7 tests pass, including both official KATs.

If `Aes256Gcm::new(key.into())` or `.encrypt(nonce.into(), payload)` doesn't compile because the `From`/generic-array conversion doesn't line up: check `cargo doc --open -p aes-gcm` for the current `AeadCore`/`KeyInit` trait bounds — the `aead`/`aes-gcm`/`chacha20poly1305` crates moved from `generic-array` to their own `array` crate recently and exact conversion paths shift between minor versions.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-crypto/src/aead.rs crates/aegis-crypto/Cargo.toml
git commit -m "aegis-crypto: AEAD wrapper with mandated nonce construction and official KATs"
```

---

### Task 4: Argon2id passphrase KDF

**Files:**
- Modify: `crates/aegis-crypto/src/passphrase.rs`

**Interfaces:**
- Produces:
  - `pub struct Argon2Params { pub memory_kib: u32, pub iterations: u32, pub parallelism: u32 }`
  - `pub const PRODUCTION_PARAMS: Argon2Params`
  - `pub fn derive_master_key(password: &[u8], salt: &[u8], secret: &[u8], associated_data: &[u8], params: &Argon2Params, output: &mut [u8]) -> Result<(), argon2::Error>`
- Consumes: nothing from earlier tasks.

Spec §2 mandates production parameters: Memory 64 MiB, Iterations 4, Parallelism 4.

- [ ] **Step 1: Write the failing tests**

Append to `crates/aegis-crypto/src/passphrase.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_params_match_spec() {
        assert_eq!(PRODUCTION_PARAMS.memory_kib, 64 * 1024);
        assert_eq!(PRODUCTION_PARAMS.iterations, 4);
        assert_eq!(PRODUCTION_PARAMS.parallelism, 4);
    }

    #[test]
    fn same_inputs_are_deterministic() {
        let params = Argon2Params {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        };
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        derive_master_key(b"password", b"somesalt12345678", b"", b"", &params, &mut out1)
            .unwrap();
        derive_master_key(b"password", b"somesalt12345678", b"", b"", &params, &mut out2)
            .unwrap();
        assert_eq!(out1, out2);
    }

    /// RFC 9106 Section 5.3 official Argon2id test vector, transcribed
    /// directly from the RFC text. Verifies our wrapper's plumbing
    /// against an official KAT.
    #[test]
    fn argon2id_official_kat_rfc9106() {
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let associated_data = [0x04u8; 12];
        let params = Argon2Params {
            memory_kib: 32,
            iterations: 3,
            parallelism: 4,
        };
        let expected_tag = hex::decode(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        )
        .unwrap();

        let mut out = vec![0u8; 32];
        derive_master_key(&password, &salt, &secret, &associated_data, &params, &mut out)
            .unwrap();
        assert_eq!(out, expected_tag);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p aegis-crypto passphrase::tests`
Expected: compile error — `Argon2Params`, `PRODUCTION_PARAMS`, `derive_master_key` don't exist yet.

- [ ] **Step 3: Write minimal implementation**

Replace `crates/aegis-crypto/src/passphrase.rs`'s contents (keep the existing doc comment):

```rust
//! Argon2id passphrase KDF. See AEGIS.Plan.V0.2.md Section 2.
//!
//! Reference: RFC 9106 (Argon2). Production parameters are fixed by
//! spec Section 2 and are not user-configurable (Security-by-Default,
//! spec Section 4/7A — no toggle may decrease these).

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Spec Section 2: Memory 64 MiB, Iterations 4, Parallelism 4.
pub const PRODUCTION_PARAMS: Argon2Params = Argon2Params {
    memory_kib: 64 * 1024,
    iterations: 4,
    parallelism: 4,
};

pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    params: &Argon2Params,
    output: &mut [u8],
) -> Result<(), argon2::Error> {
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.parallelism)
        .output_len(output.len());
    if !associated_data.is_empty() {
        builder.data(AssociatedData::new(associated_data)?);
    }
    let argon2_params = builder.build()?;

    let argon2 = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params)
    } else {
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, argon2_params)?
    };

    argon2.derive_key(password, salt, output)
}
```

(`ParamsBuilder`, `AssociatedData`, and `Argon2::derive_key`/`new_with_secret` were all confirmed directly against the live `argon2` 0.6.0 docs while writing this plan — the crate's older `Params::new(m, t, p, len)` four-argument constructor still exists but has no way to attach associated data, which is why this uses the builder instead.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p aegis-crypto passphrase::tests`
Expected: all 3 tests pass, including the official KAT.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-crypto/src/passphrase.rs
git commit -m "aegis-crypto: Argon2id passphrase KDF with official RFC 9106 KAT"
```

---

### Task 5: BLAKE3-based Short Authentication Strings

**Files:**
- Modify: `crates/aegis-crypto/src/sas.rs`

**Interfaces:**
- Produces:
  - `pub fn sas_digest(transcript: &[u8]) -> [u8; 32]`
  - `pub fn sas_display(digest: &[u8; 32]) -> String` (a numeric string for out-of-band human comparison, similar in spirit to Signal's safety numbers)
- Consumes: nothing from earlier tasks. (The ratchet layer decides what goes into `transcript` — typically both parties' identity public keys — this crate only provides the primitive.)

Reference: spec §2 — "SAS generated via BLAKE3 key hashing."

- [ ] **Step 1: Write the failing tests**

Append to `crates/aegis-crypto/src/sas.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_transcript_gives_same_digest() {
        assert_eq!(sas_digest(b"alice-pub||bob-pub"), sas_digest(b"alice-pub||bob-pub"));
    }

    #[test]
    fn different_transcript_gives_different_digest() {
        assert_ne!(sas_digest(b"alice-pub||bob-pub"), sas_digest(b"bob-pub||alice-pub"));
    }

    #[test]
    fn display_is_fixed_length_numeric() {
        let digest = sas_digest(b"some transcript");
        let display = sas_display(&digest);
        assert_eq!(display.len(), 20, "5 groups of 4 digits");
        assert!(display.chars().all(|c| c.is_ascii_digit() || c == ' '));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p aegis-crypto sas::tests`
Expected: compile error — `sas_digest`, `sas_display` don't exist yet.

- [ ] **Step 3: Write minimal implementation**

Replace `crates/aegis-crypto/src/sas.rs`'s contents (keep the existing doc comment):

```rust
//! BLAKE3-based Short Authentication Strings. See AEGIS.Plan.V0.2.md
//! Section 2. The ratchet layer supplies the transcript (typically
//! both parties' identity public keys); this module only hashes and
//! formats it for out-of-band human comparison.

/// Hash a verification transcript (e.g. both parties' identity public
/// keys, concatenated in a fixed order) with BLAKE3.
pub fn sas_digest(transcript: &[u8]) -> [u8; 32] {
    *blake3::hash(transcript).as_bytes()
}

/// Format a digest as 5 space-separated 4-digit groups (20 chars) for
/// side-by-side human comparison, in the spirit of Signal's safety
/// numbers. Uses the first 8 bytes of the digest, each pair of bytes
/// reduced mod 10000.
pub fn sas_display(digest: &[u8; 32]) -> String {
    let mut groups = Vec::with_capacity(5);
    for chunk in digest[..10].chunks(2) {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]) % 10000;
        groups.push(format!("{value:04}"));
    }
    groups.join(" ")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p aegis-crypto sas::tests`
Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/aegis-crypto/src/sas.rs
git commit -m "aegis-crypto: BLAKE3 short authentication strings"
```

---

### Task 6: Ed25519 + ML-DSA-87 dual-signature wrapper

**Files:**
- Modify: `crates/aegis-crypto/src/signature.rs`

**Interfaces:**
- Produces:
  - `pub struct DualKeyPair` with `pub fn generate() -> Self`, `pub fn ed25519_public_bytes(&self) -> [u8; 32]`, `pub fn ml_dsa87_public_bytes(&self) -> Vec<u8>`, `pub fn sign(&self, message: &[u8]) -> DualSignature`
  - `pub struct DualSignature { pub ed25519: [u8; 64], pub ml_dsa87: Vec<u8> }`
  - `pub fn verify_dual(ed25519_pub: &[u8; 32], ml_dsa87_pub: &[u8], message: &[u8], sig: &DualSignature) -> bool` — returns `true` only if **both** signatures verify (spec §2: "ML-DSA-87 paired with Ed25519").
- Consumes: nothing from earlier tasks.

- [ ] **Step 1: Write the failing tests**

Append to `crates/aegis-crypto/src/signature.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_dual_signature_verifies() {
        let keypair = DualKeyPair::generate();
        let sig = keypair.sign(b"hello aegis");
        assert!(verify_dual(
            &keypair.ed25519_public_bytes(),
            &keypair.ml_dsa87_public_bytes(),
            b"hello aegis",
            &sig,
        ));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let keypair = DualKeyPair::generate();
        let sig = keypair.sign(b"hello aegis");
        assert!(!verify_dual(
            &keypair.ed25519_public_bytes(),
            &keypair.ml_dsa87_public_bytes(),
            b"goodbye aegis",
            &sig,
        ));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let keypair = DualKeyPair::generate();
        let other = DualKeyPair::generate();
        let sig = keypair.sign(b"hello aegis");
        assert!(!verify_dual(
            &other.ed25519_public_bytes(),
            &other.ml_dsa87_public_bytes(),
            b"hello aegis",
            &sig,
        ));
    }

    #[test]
    fn tampered_ed25519_component_fails_even_if_ml_dsa87_is_valid() {
        let keypair = DualKeyPair::generate();
        let mut sig = keypair.sign(b"hello aegis");
        sig.ed25519[0] ^= 0xFF;
        assert!(!verify_dual(
            &keypair.ed25519_public_bytes(),
            &keypair.ml_dsa87_public_bytes(),
            b"hello aegis",
            &sig,
        ));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p aegis-crypto signature::tests`
Expected: compile error — `DualKeyPair`, `DualSignature`, `verify_dual` don't exist yet.

- [ ] **Step 3: Write minimal implementation**

Replace `crates/aegis-crypto/src/signature.rs`'s contents (keep the existing doc comment):

```rust
//! Ed25519 + ML-DSA-87 dual-signature wrapper (NIST FIPS 204). See
//! AEGIS.Plan.V0.2.md Section 2. A signature is only considered valid
//! if BOTH the Ed25519 and ML-DSA-87 components verify — this is what
//! "ML-DSA-87 paired with Ed25519" means in the spec.

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey, Verifier as _, VerifyingKey as Ed25519VerifyingKey};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, SigningKey as MlDsa87SigningKey, VerifyingKey as MlDsa87VerifyingKey};
use signature::{Signer as _, Verifier as _};

pub struct DualKeyPair {
    ed25519: Ed25519SigningKey,
    ml_dsa87: MlDsa87SigningKey<MlDsa87>,
}

pub struct DualSignature {
    pub ed25519: [u8; 64],
    pub ml_dsa87: Vec<u8>,
}

impl DualKeyPair {
    /// Both component keys are generated from independent
    /// securely-random 32-byte seeds via `getrandom` — the same
    /// `from_seed` construction the ML-DSA-87 ACVP KAT (Task 6, Step 5)
    /// verifies deterministically, just with real OS randomness here
    /// instead of a fixed test seed.
    pub fn generate() -> Self {
        let mut ed25519_seed = [0u8; 32];
        getrandom::fill(&mut ed25519_seed).expect("OS RNG failure");
        let ed25519 = Ed25519SigningKey::from_bytes(&ed25519_seed);

        let mut ml_dsa87_seed = [0u8; 32];
        getrandom::fill(&mut ml_dsa87_seed).expect("OS RNG failure");
        let ml_dsa87 = MlDsa87SigningKey::<MlDsa87>::from_seed(&ml_dsa87_seed.into());

        Self { ed25519, ml_dsa87 }
    }

    pub fn ed25519_public_bytes(&self) -> [u8; 32] {
        self.ed25519.verifying_key().to_bytes()
    }

    pub fn ml_dsa87_public_bytes(&self) -> Vec<u8> {
        self.ml_dsa87.verifying_key().encode().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> DualSignature {
        let ed25519 = self.ed25519.sign(message).to_bytes();
        let ml_dsa87 = self.ml_dsa87.sign(message).encode().to_vec();
        DualSignature { ed25519, ml_dsa87 }
    }
}

pub fn verify_dual(
    ed25519_pub: &[u8; 32],
    ml_dsa87_pub: &[u8],
    message: &[u8],
    sig: &DualSignature,
) -> bool {
    let ed25519_ok = Ed25519VerifyingKey::from_bytes(ed25519_pub)
        .ok()
        .and_then(|vk| {
            let sig = ed25519_dalek::Signature::from_bytes(&sig.ed25519);
            vk.verify(message, &sig).ok()
        })
        .is_some();

    // ML-DSA-87's `decode` takes an already-correctly-sized encoded key/
    // signature and is infallible; the fallible part is the initial
    // `try_from` size check on attacker-controlled byte lengths — same
    // two-step shape the crate's own ACVP test harness uses (Task 6,
    // Step 5).
    let ml_dsa87_ok = EncodedVerifyingKey::<MlDsa87>::try_from(ml_dsa87_pub)
        .ok()
        .and_then(|encoded_vk| {
            let vk = MlDsa87VerifyingKey::decode(&encoded_vk);
            let encoded_sig = EncodedSignature::<MlDsa87>::try_from(sig.ml_dsa87.as_slice()).ok()?;
            let signature = ml_dsa::Signature::<MlDsa87>::decode(&encoded_sig)?;
            vk.verify(message, &signature).ok()
        })
        .is_some();

    ed25519_ok && ml_dsa87_ok
}
```

`SigningKey::from_seed`, `.verifying_key()`, and `.encode()` were confirmed directly from the `ml-dsa` crate's own ACVP test harness source (`RustCrypto/signatures`, `ml-dsa/tests/key-gen.rs`) while writing this plan — the same source Task 6 Step 5's KAT test mirrors. If `EncodedVerifyingKey`/`EncodedSignature`'s `try_from`/`decode` names have moved in the exact version resolved, `cargo doc --open -p ml-dsa` will show the current ones; the round-trip tests above and the ACVP KAT in Step 5 will both confirm correctness either way.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p aegis-crypto signature::tests`
Expected: all 4 tests pass.

- [ ] **Step 5: Add the official ML-DSA-87 ACVP KAT**

Spec §9.1 requires an official KAT for ML-DSA-87, not just round-trip
tests. Fetch the same real NIST ACVP-derived fixture the `ml-dsa` crate
tests itself against (RustCrypto/signatures) — do not hand-write it:

```bash
mkdir -p crates/aegis-crypto/tests/vectors
curl -o crates/aegis-crypto/tests/vectors/ml-dsa-key-gen.json \
  https://raw.githubusercontent.com/RustCrypto/signatures/master/ml-dsa/tests/key-gen.json
```

Create `crates/aegis-crypto/tests/ml_dsa_acvp.rs`, mirroring the exact
parsing pattern `ml-dsa`'s own `tests/key-gen.rs` uses (fetch that file
with `curl https://raw.githubusercontent.com/RustCrypto/signatures/master/ml-dsa/tests/key-gen.rs`
if anything below doesn't line up — confirmed field names as of this
plan's research are `seed`, `pk`, `sk`):

```rust
//! Official NIST ACVP key-generation KAT for ML-DSA-87, filtered from
//! the same fixture file the `ml-dsa` crate tests itself against
//! (RustCrypto/signatures, ml-dsa/tests/key-gen.json). Verifies
//! deterministic key generation against an official KAT per spec
//! Section 9.1. This exercises the underlying `ml_dsa` crate directly
//! (seed-based generation), not our `DualKeyPair` wrapper — production
//! code always generates from secure randomness, never a fixed seed,
//! so `DualKeyPair` intentionally has no seed-based constructor.

use ml_dsa::{EncodedVerifyingKey, MlDsa87, MlDsaParams, SigningKey, VerifyingKey};
use serde::Deserialize;
use signature::Keypair;
use std::fs;

#[derive(Deserialize)]
struct TestVectorFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Deserialize)]
struct TestGroup {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    tests: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    seed: String,
    pk: String,
}

#[test]
fn acvp_ml_dsa_87_key_gen() {
    let json = fs::read_to_string("tests/vectors/ml-dsa-key-gen.json").unwrap();
    let file: TestVectorFile = serde_json::from_str(&json).unwrap();

    let group = file
        .test_groups
        .iter()
        .find(|g| g.parameter_set == "ML-DSA-87")
        .expect("fixture file has an ML-DSA-87 test group");
    let case = &group.tests[0];

    let seed_bytes = hex::decode(&case.seed).unwrap();
    let expected_pk = hex::decode(&case.pk).unwrap();

    let seed = seed_bytes.as_slice().try_into().expect("32-byte seed");
    let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);
    let verifying_key = signing_key.verifying_key();

    assert_eq!(
        verifying_key.encode().as_slice(),
        expected_pk.as_slice()
    );
}
```

If `MlDsaParams`/`EncodedVerifyingKey`/`from_seed`/`encode` don't match
this exact version's API: check the fetched `key-gen.rs` reference
above for the confirmed current names — same guidance as Task 7.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p aegis-crypto signature ml_dsa_acvp`
Expected: all unit tests plus the ACVP integration test pass.

- [ ] **Step 7: Commit**

```bash
git add crates/aegis-crypto/src/signature.rs crates/aegis-crypto/tests/
git commit -m "aegis-crypto: Ed25519 + ML-DSA-87 dual-signature wrapper with official ACVP KAT"
```

---

### Task 7: ML-KEM-1024 wrapper with official ACVP KAT

**Files:**
- Modify: `crates/aegis-crypto/src/kem.rs`
- Create: `crates/aegis-crypto/tests/vectors/ml-kem-key-gen.json` (fetched, not hand-written — see Step 3)

**Interfaces:**
- Produces:
  - `pub struct MlKem1024KeyPair` with `pub fn generate() -> Self`, `pub fn encapsulation_key_bytes(&self) -> Vec<u8>`
  - `pub fn ml_kem_encapsulate(encapsulation_key_bytes: &[u8]) -> (Vec<u8>, [u8; 32])` returning `(ciphertext, shared_secret)`
  - `pub fn ml_kem_decapsulate(keypair: &MlKem1024KeyPair, ciphertext: &[u8]) -> [u8; 32]`
- Consumes: nothing from earlier tasks.

- [ ] **Step 1: Fetch the official ACVP KAT file**

This is a real NIST ACVP-derived fixture already vendored by the `ml-kem` crate itself (RustCrypto/KEMs) — do not hand-write it.

```bash
curl -o crates/aegis-crypto/tests/vectors/ml-kem-key-gen.json \
  https://raw.githubusercontent.com/RustCrypto/KEMs/master/ml-kem/tests/key-gen.json
```

- [ ] **Step 2: Write the failing tests**

Append to `crates/aegis-crypto/src/kem.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_then_decapsulate_recovers_shared_secret() {
        let keypair = MlKem1024KeyPair::generate();
        let (ciphertext, sender_secret) = ml_kem_encapsulate(&keypair.encapsulation_key_bytes());
        let receiver_secret = ml_kem_decapsulate(&keypair, &ciphertext);
        assert_eq!(sender_secret, receiver_secret);
    }

    #[test]
    fn different_keypairs_produce_different_shared_secrets() {
        let a = MlKem1024KeyPair::generate();
        let b = MlKem1024KeyPair::generate();
        let (_, secret_a) = ml_kem_encapsulate(&a.encapsulation_key_bytes());
        let (_, secret_b) = ml_kem_encapsulate(&b.encapsulation_key_bytes());
        assert_ne!(secret_a, secret_b);
    }
}
```

Create `crates/aegis-crypto/tests/ml_kem_acvp.rs` (an integration test, mirroring the exact parsing pattern `ml-kem`'s own `tests/key-gen.rs` uses — fetch that file with `curl https://raw.githubusercontent.com/RustCrypto/KEMs/master/ml-kem/tests/key-gen.rs` to see the reference implementation if anything below doesn't line up):

```rust
//! Official NIST ACVP key-generation KAT for ML-KEM-1024, filtered from
//! the same fixture file the `ml-kem` crate tests itself against
//! (RustCrypto/KEMs, ml-kem/tests/key-gen.json). Verifies our wrapper's
//! deterministic key generation against an official KAT per spec
//! Section 9.1.

use ml_kem::{FromSeed, Kem, KeyExport, MlKem1024};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TestVectorFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Deserialize)]
struct TestGroup {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    tests: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    d: String,
    z: String,
    ek: String,
}

#[test]
fn acvp_ml_kem_1024_key_gen() {
    let json = fs::read_to_string("tests/vectors/ml-kem-key-gen.json").unwrap();
    let file: TestVectorFile = serde_json::from_str(&json).unwrap();

    let group = file
        .test_groups
        .iter()
        .find(|g| g.parameter_set == "ML-KEM-1024")
        .expect("fixture file has an ML-KEM-1024 test group");
    let case = &group.tests[0];

    let d = hex::decode(&case.d).unwrap();
    let z = hex::decode(&case.z).unwrap();
    let expected_ek = hex::decode(&case.ek).unwrap();

    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&d);
    seed[32..].copy_from_slice(&z);

    let (_dk, ek) = MlKem1024::from_seed(&seed.into());
    assert_eq!(ek.to_bytes().to_vec(), expected_ek);
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p aegis-crypto kem`
Expected: compile errors — `MlKem1024KeyPair`, `ml_kem_encapsulate`, `ml_kem_decapsulate` don't exist yet.

- [ ] **Step 4: Write minimal implementation**

Replace `crates/aegis-crypto/src/kem.rs`'s contents (keep the existing doc comment):

```rust
//! ML-KEM-1024 wrapper (NIST FIPS 203). See AEGIS.Plan.V0.2.md Section 2.
//!
//! Uses `encapsulate_deterministic` (fed with our own OS-random 32-byte
//! value via `getrandom`) rather than the crate's `Encapsulate` trait,
//! which otherwise needs a `rand_core::CryptoRng` implementation we'd
//! have to adapt `getrandom` into ourselves — this achieves the same
//! thing without an extra adapter type.

use ml_kem::{
    array::Array, Ciphertext, Decapsulate, EncapsulationKey, FromSeed, Key, KeyExport, MlKem1024,
    B32,
};

pub struct MlKem1024KeyPair {
    decapsulation_key: ml_kem::DecapsulationKey<MlKem1024>,
    encapsulation_key: EncapsulationKey<MlKem1024>,
}

impl MlKem1024KeyPair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 64];
        getrandom::fill(&mut seed).expect("OS RNG failure");
        let (decapsulation_key, encapsulation_key) = MlKem1024::from_seed(&seed.into());
        Self {
            decapsulation_key,
            encapsulation_key,
        }
    }

    pub fn encapsulation_key_bytes(&self) -> Vec<u8> {
        self.encapsulation_key.to_bytes().to_vec()
    }
}

pub fn ml_kem_encapsulate(encapsulation_key_bytes: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let key_array: Key<EncapsulationKey<MlKem1024>> =
        Array::try_from(encapsulation_key_bytes).expect("wrong encapsulation key length");
    let ek = EncapsulationKey::<MlKem1024>::new(&key_array).expect("invalid encapsulation key");

    let mut randomness = [0u8; 32];
    getrandom::fill(&mut randomness).expect("OS RNG failure");
    let m: B32 = randomness.into();

    let (ciphertext, shared_secret) = ek.encapsulate_deterministic(&m);
    (ciphertext.to_vec(), shared_secret.into())
}

pub fn ml_kem_decapsulate(keypair: &MlKem1024KeyPair, ciphertext: &[u8]) -> [u8; 32] {
    let ct: Ciphertext<MlKem1024> =
        Array::try_from(ciphertext).expect("wrong ciphertext length");
    keypair.decapsulation_key.decapsulate(&ct).into()
}
```

`encapsulate_deterministic` is marked `#[doc(hidden)]` unless the crate's
`hazmat` feature is enabled, but it is still `pub` and callable either
way — the `#[doc(hidden)]` only affects whether it shows up in
`cargo doc` output, confirmed directly from the `ml-kem` crate's source
(`encapsulation_key.rs`) while writing this plan. If a future version
gates it behind an actual `#[cfg(feature = "hazmat")]` compile-time
guard instead, add that feature: `cargo add ml-kem --features hazmat -p aegis-crypto`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p aegis-crypto kem`
Expected: both unit tests and the ACVP integration test pass.

- [ ] **Step 6: Commit**

```bash
git add crates/aegis-crypto/src/kem.rs crates/aegis-crypto/tests/
git commit -m "aegis-crypto: ML-KEM-1024 wrapper with official ACVP KAT"
```

---

### Task 8: brainpoolP512r1 ECDH via `bp512-nestler`

**Files:**
- Modify: `crates/aegis-crypto/Cargo.toml`
- Modify: `crates/aegis-crypto/src/ecdh.rs`
- Create: `vendor/hybrid-array-0.4.14/` (copied from `bp512-nestler`'s own source, per its README)
- Modify: `Cargo.toml` (workspace root — the `[patch.crates-io]` block)

**Interfaces:**
- Produces:
  - `pub struct Brainpool512SecretKey` with `pub fn generate() -> Self`, `pub fn public_key_bytes(&self) -> Vec<u8>`
  - `pub fn brainpool512_diffie_hellman(secret: &Brainpool512SecretKey, peer_public_bytes: &[u8]) -> [u8; 64]`
- Consumes: nothing from earlier tasks.

**Context for whoever implements this:** no `brainpool512r1` crate exists in the RustCrypto ecosystem (`bp256`/`bp384` exist, `bp512` doesn't — confirmed by direct lookup against crates.io and the RustCrypto/elliptic-curves GitHub repo while writing this plan). `bp512-nestler` is a real, published crate (v0.1.2, PolyForm-Noncommercial-1.0.0 license) implementing this curve via the same `elliptic-curve`/`primefield`/`primeorder` generic framework RustCrypto's own `bp384` uses, with domain parameters cross-verified against RFC 5639 §3.7 and OpenSSL, and its own ECDH checked against an independent oracle. It needs one one-time vendor patch before it builds — see Step 1.

- [ ] **Step 1: Apply the required vendor patch**

```bash
mkdir -p vendor/hybrid-array-0.4.14
curl -o /tmp/hybrid-array-patch.tar "https://api.github.com/repos/Basty-devel/bp512-nestler/tarball/main"
```

(If `curl`/tarball extraction is awkward in your shell, instead browse to
`https://github.com/Basty-devel/bp512-nestler/tree/main/vendor-patch/hybrid-array-0.4.14`
and download that folder's contents directly into `vendor/hybrid-array-0.4.14/` at
the AEGIS workspace root.)

Inside your copy of `vendor/hybrid-array-0.4.14/`, rename `Cargo.toml.vendor-copy`
back to `Cargo.toml` (per the `bp512-nestler` README — it ships renamed so the
upstream crate isn't flagged as bundling a nested package).

Add to the **workspace root** `C:\AEGIS\Cargo.toml` (not any crate's own
`Cargo.toml`):

```toml
[patch.crates-io]
hybrid-array = { path = "vendor/hybrid-array-0.4.14" }
```

This is a one-line addition of a missing const-generic array-size table
entry (`513 => U513,`) that `primeorder::PrimeCurveParams` needs for this
curve's 512-bit scalar — already merged upstream, not yet released. Delete
this patch block and the `vendor/` copy once `hybrid-array` ships a release
covering size 513 (tracked at
[RustCrypto/hybrid-array#66](https://github.com/RustCrypto/hybrid-array/issues/66)).

- [ ] **Step 2: Add the dependency**

```bash
cargo add bp512-nestler -p aegis-crypto
```

- [ ] **Step 3: Write the failing tests**

Append to `crates/aegis-crypto/src/ecdh.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_shared_secret() {
        let alice = Brainpool512SecretKey::generate();
        let bob = Brainpool512SecretKey::generate();

        let alice_shared = brainpool512_diffie_hellman(&alice, &bob.public_key_bytes());
        let bob_shared = brainpool512_diffie_hellman(&bob, &alice.public_key_bytes());

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn different_peers_give_different_shared_secrets() {
        let alice = Brainpool512SecretKey::generate();
        let bob = Brainpool512SecretKey::generate();
        let carol = Brainpool512SecretKey::generate();

        let alice_bob = brainpool512_diffie_hellman(&alice, &bob.public_key_bytes());
        let alice_carol = brainpool512_diffie_hellman(&alice, &carol.public_key_bytes());

        assert_ne!(alice_bob, alice_carol);
    }
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p aegis-crypto ecdh::tests`
Expected: compile error — `Brainpool512SecretKey`, `brainpool512_diffie_hellman` don't exist yet.

- [ ] **Step 5: Write minimal implementation**

Replace `crates/aegis-crypto/src/ecdh.rs`'s contents (keep the existing doc comment):

```rust
//! brainpoolP512r1 ECDH. See AEGIS.Plan.V0.2.md Section 2.
//!
//! Uses `bp512-nestler` (see this crate's Cargo.toml and the workspace
//! root's `[patch.crates-io]` block) since no brainpool512r1
//! implementation exists in the mainline RustCrypto ecosystem as of
//! this writing. Domain parameters: RFC 5639 Section 3.7.

use bp512_nestler::BrainpoolP512r1;
use elliptic_curve::{
    sec1::{FromSec1Point, ToSec1Point},
    PublicKey, SecretKey,
};

pub struct Brainpool512SecretKey(SecretKey<BrainpoolP512r1>);

impl Brainpool512SecretKey {
    pub fn generate() -> Self {
        loop {
            let mut bytes = elliptic_curve::FieldBytes::<BrainpoolP512r1>::default();
            getrandom::fill(&mut bytes).expect("OS RNG failure");
            if let Ok(secret) = SecretKey::<BrainpoolP512r1>::from_bytes(&bytes) {
                return Self(secret);
            }
            // Rejection sampling: retry on the astronomically rare case
            // the raw bytes aren't a valid nonzero scalar below the
            // curve order.
        }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0
            .public_key()
            .to_sec1_bytes()
            .to_vec()
    }
}

pub fn brainpool512_diffie_hellman(
    secret: &Brainpool512SecretKey,
    peer_public_bytes: &[u8],
) -> [u8; 64] {
    let peer_public = PublicKey::<BrainpoolP512r1>::from_sec1_bytes(peer_public_bytes)
        .expect("invalid peer public key encoding");
    let shared = secret.0.diffie_hellman(&peer_public);
    let mut out = [0u8; 64];
    out.copy_from_slice(shared.raw_secret_bytes());
    out
}
```

`to_sec1_bytes`/`from_sec1_bytes` (via the `ToSec1Point`/`FromSec1Point`
traits) and `SecretKey::diffie_hellman` returning a `SharedSecret` with
`raw_secret_bytes()` were all confirmed directly against the live
`elliptic-curve` 0.14.1 docs while writing this plan — not guessed from
memory. If a resolved version still differs, the two round-trip tests
in Step 3 will fail with a clear compile error pointing at whichever
name moved.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p aegis-crypto ecdh::tests`
Expected: both tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/aegis-crypto/Cargo.toml crates/aegis-crypto/src/ecdh.rs vendor/ Cargo.toml
git commit -m "aegis-crypto: brainpoolP512r1 ECDH via bp512-nestler, with required vendor patch"
```

---

### Task 9: Hybrid KEM combiner and protocol version table

**Files:**
- Modify: `crates/aegis-crypto/src/hybrid.rs`
- Modify: `crates/aegis-crypto/src/version.rs`

**Interfaces:**
- Consumes:
  - `kdf::derive_key` (Task 2)
  - `kem::{MlKem1024KeyPair, ml_kem_encapsulate, ml_kem_decapsulate}` (Task 7)
  - `ecdh::{Brainpool512SecretKey, brainpool512_diffie_hellman}` (Task 8)
- Produces:
  - `pub struct HybridPublicKeys { pub brainpool512: Vec<u8>, pub ml_kem1024_ek: Vec<u8> }`
  - `pub struct HybridCiphertext { pub brainpool512_ephemeral_public: Vec<u8>, pub ml_kem1024_ciphertext: Vec<u8> }`
  - `pub fn hybrid_kem_encapsulate(protocol_version: u8, peer_keys: &HybridPublicKeys) -> (HybridCiphertext, [u8; 32])`
  - `pub fn hybrid_kem_decapsulate(protocol_version: u8, our_brainpool_secret: &Brainpool512SecretKey, our_ml_kem: &MlKem1024KeyPair, our_public_keys: &HybridPublicKeys, ciphertext: &HybridCiphertext) -> [u8; 32]`
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum ProtocolVersion { V1 = 1 }`
  - `pub fn parse_protocol_version(byte: u8) -> Option<ProtocolVersion>`

This implements spec §2's exact formula: `K = HKDF-SHA512(SS_brainpool512r1 || SS_ML-KEM-1024, info = domain_label || protocol_version || pubkey_A || pubkey_B)`.

- [ ] **Step 1: Write the failing tests**

Append to `crates/aegis-crypto/src/version.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_version_byte_parses() {
        assert_eq!(parse_protocol_version(1), Some(ProtocolVersion::V1));
    }

    #[test]
    fn unknown_version_byte_is_rejected() {
        assert_eq!(parse_protocol_version(99), None);
    }
}
```

Append to `crates/aegis-crypto/src/hybrid.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdh::Brainpool512SecretKey;
    use crate::kem::MlKem1024KeyPair;

    fn keys_for(brainpool: &Brainpool512SecretKey, ml_kem: &MlKem1024KeyPair) -> HybridPublicKeys {
        HybridPublicKeys {
            brainpool512: brainpool.public_key_bytes(),
            ml_kem1024_ek: ml_kem.encapsulation_key_bytes(),
        }
    }

    #[test]
    fn both_sides_derive_the_same_hybrid_key() {
        let alice_brainpool = Brainpool512SecretKey::generate();
        let alice_ml_kem = MlKem1024KeyPair::generate();
        let alice_public = keys_for(&alice_brainpool, &alice_ml_kem);

        let (ciphertext, sender_key) = hybrid_kem_encapsulate(1, &alice_public);
        let receiver_key = hybrid_kem_decapsulate(
            1,
            &alice_brainpool,
            &alice_ml_kem,
            &alice_public,
            &ciphertext,
        );

        assert_eq!(sender_key, receiver_key);
    }

    #[test]
    fn different_protocol_versions_derive_different_keys() {
        let brainpool = Brainpool512SecretKey::generate();
        let ml_kem = MlKem1024KeyPair::generate();
        let public = keys_for(&brainpool, &ml_kem);

        let (ciphertext_v1, key_v1) = hybrid_kem_encapsulate(1, &public);
        let key_v1_decap = hybrid_kem_decapsulate(1, &brainpool, &ml_kem, &public, &ciphertext_v1);
        assert_eq!(key_v1, key_v1_decap);

        // Re-deriving with a mismatched version byte on the decapsulating
        // side must NOT produce the same key as the sender used — proves
        // the version byte is actually bound into the KDF info, not
        // decorative.
        let key_wrong_version =
            hybrid_kem_decapsulate(2, &brainpool, &ml_kem, &public, &ciphertext_v1);
        assert_ne!(key_v1, key_wrong_version);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p aegis-crypto hybrid version`
Expected: compile errors — none of the hybrid/version items exist yet.

- [ ] **Step 3: Write minimal implementation**

Replace `crates/aegis-crypto/src/version.rs`'s contents (keep the existing doc comment):

```rust
//! Protocol version and algorithm-suite negotiation table. See
//! AEGIS.Plan.V0.2.md Section 2 (crypto-agility requirement).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1 = 1,
}

pub fn parse_protocol_version(byte: u8) -> Option<ProtocolVersion> {
    match byte {
        1 => Some(ProtocolVersion::V1),
        _ => None,
    }
}
```

Replace `crates/aegis-crypto/src/hybrid.rs`'s contents (keep the existing doc comment):

```rust
//! Hybrid ML-KEM-1024 + brainpool512r1 KEM combiner. See
//! AEGIS.Plan.V0.2.md Section 2.
//!
//! Construction: `K = HKDF-SHA512(SS_brainpool512r1 || SS_ML-KEM-1024,
//! info = domain_label || protocol_version || pubkey_A || pubkey_B)`.
//! Reference: NIST SP 800-56C (concatenation KDF combiner).

use crate::ecdh::{brainpool512_diffie_hellman, Brainpool512SecretKey};
use crate::kdf::derive_key;
use crate::kem::{ml_kem_decapsulate, ml_kem_encapsulate, MlKem1024KeyPair};

const DOMAIN_LABEL: &[u8] = b"AegisPQC-v1-HybridKEM";

pub struct HybridPublicKeys {
    pub brainpool512: Vec<u8>,
    pub ml_kem1024_ek: Vec<u8>,
}

pub struct HybridCiphertext {
    pub brainpool512_ephemeral_public: Vec<u8>,
    pub ml_kem1024_ciphertext: Vec<u8>,
}

/// Encapsulate to `peer_keys`, generating a fresh ephemeral
/// brainpool512r1 keypair for this exchange. Returns the ciphertext
/// bundle to send and the resulting 32-byte shared key.
pub fn hybrid_kem_encapsulate(
    protocol_version: u8,
    peer_keys: &HybridPublicKeys,
) -> (HybridCiphertext, [u8; 32]) {
    let ephemeral_brainpool = Brainpool512SecretKey::generate();
    let brainpool_shared =
        brainpool512_diffie_hellman(&ephemeral_brainpool, &peer_keys.brainpool512);
    let (ml_kem_ciphertext, ml_kem_shared) = ml_kem_encapsulate(&peer_keys.ml_kem1024_ek);

    let mut ikm = Vec::with_capacity(brainpool_shared.len() + ml_kem_shared.len());
    ikm.extend_from_slice(&brainpool_shared);
    ikm.extend_from_slice(&ml_kem_shared);

    let mut key = [0u8; 32];
    derive_key(
        &ikm,
        DOMAIN_LABEL,
        protocol_version,
        &ephemeral_brainpool.public_key_bytes(),
        &peer_keys.brainpool512,
        &mut key,
    )
    .expect("HKDF output length is valid");

    (
        HybridCiphertext {
            brainpool512_ephemeral_public: ephemeral_brainpool.public_key_bytes(),
            ml_kem1024_ciphertext: ml_kem_ciphertext,
        },
        key,
    )
}

/// Decapsulate a bundle produced by [`hybrid_kem_encapsulate`] using
/// our own long-term keys.
pub fn hybrid_kem_decapsulate(
    protocol_version: u8,
    our_brainpool_secret: &Brainpool512SecretKey,
    our_ml_kem: &MlKem1024KeyPair,
    our_public_keys: &HybridPublicKeys,
    ciphertext: &HybridCiphertext,
) -> [u8; 32] {
    let brainpool_shared = brainpool512_diffie_hellman(
        our_brainpool_secret,
        &ciphertext.brainpool512_ephemeral_public,
    );
    let ml_kem_shared = ml_kem_decapsulate(our_ml_kem, &ciphertext.ml_kem1024_ciphertext);

    let mut ikm = Vec::with_capacity(brainpool_shared.len() + ml_kem_shared.len());
    ikm.extend_from_slice(&brainpool_shared);
    ikm.extend_from_slice(&ml_kem_shared);

    let mut key = [0u8; 32];
    derive_key(
        &ikm,
        DOMAIN_LABEL,
        protocol_version,
        &ciphertext.brainpool512_ephemeral_public,
        &our_public_keys.brainpool512,
        &mut key,
    )
    .expect("HKDF output length is valid");

    key
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p aegis-crypto hybrid version`
Expected: all 4 tests pass.

- [ ] **Step 5: Run the full crate test suite**

Run: `cargo test -p aegis-crypto`
Expected: every test from Tasks 1–9 passes, zero warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/aegis-crypto/src/hybrid.rs crates/aegis-crypto/src/version.rs
git commit -m "aegis-crypto: hybrid KEM combiner and protocol version table"
```

---

## Definition of Done

- `cargo test --workspace` passes with zero failures and zero warnings.
- `cargo build --workspace` still succeeds (other 6 crates remain untouched, still empty).
- Every module's doc comment cites the published construction/reference it wraps (spec §9.1) — re-read each file's top comment as a final check.
- `aegis_crypto::SECURITY_DISCLAIMER` is present and non-empty.
- The workspace root `Cargo.toml` still has `unsafe_code = "deny"`, and `aegis-crypto` has added no override — confirm with `grep -r "allow(unsafe_code)" crates/aegis-crypto/` returning nothing.
