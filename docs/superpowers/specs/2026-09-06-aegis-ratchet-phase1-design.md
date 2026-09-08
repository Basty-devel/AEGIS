# aegis-ratchet Phase 1: PQ-X3DH + Double Ratchet — Design

**Status:** Approved for implementation planning.
**Scope:** The pairwise handshake and per-message ratchet state machine
only. Sender-keys groups (spec §3.1) and multi-device device lists
(spec §3.2) are explicitly out of scope — each gets its own
brainstorm → spec → plan cycle once this phase's session API exists to
build on.
**Depends on:** `aegis-crypto` only (published, v0.1.1). No dependency
on `aegis-vault`, `aegis-net`, or any I/O/async runtime.
**Spec reference:** `AEGIS.Plan.V0.2.md` Section 3 (items 1–3 only,
not 3.1/3.2).

## 1. Architecture

`aegis-ratchet` is a pure, synchronous, allocation-only state machine.
It performs no network I/O, no disk I/O, and depends on no async
runtime. The crate's entire public surface is:

- Two handshake entry points that consume a peer's pre-key bundle and
  produce an initial `RatchetState`.
- Two per-message entry points that advance a `&mut RatchetState` and
  produce/consume ciphertext bytes.
- Byte (de)serialization for `RatchetState`, so a caller can persist it
  via `aegis-vault` (a later crate) or hold it in memory — this crate
  has no opinion on where the bytes live.

This mirrors the crate dependency graph in the spec's mandatory build
order: `aegis-net` depends on `aegis-ratchet`, not the reverse, and
`aegis-vault` depends only on `aegis-crypto`. If `aegis-ratchet` took a
storage or transport dependency, that graph would need to change.

## 2. PQ-X3DH Handshake

Extends Signal's [X3DH](https://signal.org/docs/specifications/x3dh/)
from a 3-DH combiner to a hybrid 4-leg combiner (3 classical DH legs
unchanged, plus one ML-KEM-1024 encapsulation leg), following the same
"never invent a novel construction" discipline as `aegis-crypto` — the
combiner shape is Signal's, the individual primitives are `aegis-crypto`'s.

### 2.1 Pre-key bundle

```rust
pub struct PreKeyBundle {
    pub identity_key: DualVerifyingKey,      // aegis_crypto::signature — Ed25519 + ML-DSA-87
    pub signed_pre_key: SignedPreKey,
    pub one_time_pre_key: Option<OneTimePreKey>,
}

pub struct SignedPreKey {
    pub ecdh_public: brainpool512r1 public key,      // aegis_crypto::ecdh
    pub kem_encapsulation_key: ml_kem::EncapsulationKey1024,
    pub signature: DualSignature,   // over ecdh_public || kem_encapsulation_key
}

pub struct OneTimePreKey {
    pub id: u32,                                      // for bundle-consumption bookkeeping
    pub ecdh_public: brainpool512r1 public key,
    pub kem_encapsulation_key: ml_kem::EncapsulationKey1024,
    // unsigned, single-use — matches Signal's OPK, consumed and discarded on use
}
```

### 2.2 Shared secret derivation

The initiator (Alice, holding an ephemeral brainpool512r1 keypair `EK_A`
and having generated ML-KEM-1024 ciphertexts against the bundle's
encapsulation keys) computes:

```
DH1 = ECDH(Alice_identity_ecdh, Bob_signed_pre_key.ecdh_public)
DH2 = ECDH(EK_A, Bob_identity_ecdh)
DH3 = ECDH(EK_A, Bob_signed_pre_key.ecdh_public)
KEM1 = ML-KEM-1024 encapsulate against Bob_signed_pre_key.kem_encapsulation_key
KEM2 = ML-KEM-1024 encapsulate against Bob_one_time_pre_key.kem_encapsulation_key (if present)

IKM = DH1 || DH2 || DH3 || KEM1.shared_secret || (KEM2.shared_secret if present)
root_key = HKDF-SHA512(salt = None, IKM, info = "AEGIS-X3DH-v1" || protocol_version
                        || Alice_identity_pubkey || Bob_identity_pubkey)
```

Uses `aegis_crypto::kdf`'s existing HKDF-SHA512 primitive directly with
a **new** domain-separation label distinct from `hybrid::hybrid_kem_encapsulate`'s
(that function's label is scoped to its own protocol context per spec
§9.1's citation-and-domain-separation discipline — reusing it here
would conflate two different protocols under one label). The responder
(Bob) computes the identical `IKM` from his private keys and Alice's
ephemeral/ciphertext material and must derive the same `root_key`
(verified by the two-party agreement test, §6).

Immediately after derivation: `EK_A`'s private key, the raw DH outputs,
and the raw KEM shared secrets are zeroized. Only `root_key` (itself
`Zeroizing`-wrapped) survives into `RatchetState`.

### 2.3 Initial handshake message wire format

Alice sends Bob everything he needs to recompute `IKM` without a
pre-key bundle round-trip (standard X3DH asynchronity):

```
AegisX3DHInitialMessage {
    protocol_version: u8,
    alice_identity_pubkey: [u8; DUAL_VERIFYING_KEY_LEN],
    alice_ephemeral_ecdh_pubkey: [u8; 65],       // brainpool512r1 uncompressed point
    kem_ciphertext_signed: [u8; 1568],           // ML-KEM-1024 ciphertext vs. signed pre-key
    used_one_time_pre_key_id: Option<u32>,       // 0x00 sentinel = None, else 0x01 || id
    kem_ciphertext_onetime: Option<[u8; 1568]>,  // present iff used_one_time_pre_key_id is Some
    first_message: RatchetMessage,               // §4.3 — the actual first encrypted payload
}
```

All fixed-size fields concatenated in field order; `Option` fields use
an explicit presence byte, matching `aegis-crypto`'s existing manual
byte-encoding convention (no `serde` in this crate's production
dependencies, matching the earlier design decision).

## 3. Double Ratchet State

```rust
pub struct RatchetState {
    root_key: Zeroizing<[u8; 64]>,
    sending_chain: Option<ChainState>,
    receiving_chain: Option<ChainState>,
    // Our current ratchet keypair (rotated every time we start a new sending chain)
    self_ratchet_ecdh: brainpool512r1 keypair,
    self_ratchet_kem: ml_kem DecapsulationKey,
    // The peer's most recently observed ratchet public keys, for the next DH ratchet step
    peer_ratchet_ecdh_public: Option<brainpool512r1 public key>,
    peer_ratchet_kem_public: Option<ml_kem EncapsulationKey1024>,
    // Skipped-key cache: (peer_ratchet_ecdh_public, message_number) -> message_key
    skipped_message_keys: SkippedKeyCache,       // bounded to 1000 entries, §5
    send_message_number: u32,
    receive_message_number: u32,
}

struct ChainState {
    chain_key: Zeroizing<[u8; 64]>,
}
```

### 3.1 KDF chains

Adapted from Signal's Double Ratchet
[KDF_RK/KDF_CK](https://signal.org/docs/specifications/doubleratchet/#external-functions)
(HMAC-SHA256 there → HMAC-SHA512 here, for consistency with the rest of
`aegis-crypto`, which is SHA-512-based throughout):

```
KDF_RK(root_key, hybrid_shared_secret) -> (new_root_key, chain_key)
    = HKDF-SHA512(salt = root_key, IKM = hybrid_shared_secret,
                   info = "AEGIS-RATCHET-RK-v1"), first 64 bytes = new_root_key,
                   next 64 bytes = chain_key    (single HKDF-Expand call, 128-byte output)

KDF_CK(chain_key) -> (new_chain_key, message_key)
    new_chain_key = HMAC-SHA512(key = chain_key, data = 0x02)
    message_key_material = HMAC-SHA512(key = chain_key, data = 0x01)
    message_key = message_key_material[0..32]   // truncated for AES-256-GCM / ChaCha20-Poly1305
```

`hybrid_shared_secret` for a DH ratchet step is a **fresh** ML-KEM-1024
+ brainpool512r1 pair generated at that step (spec §3 item 2: "every
message roundtrip injects a new ML-KEM-1024 encapsulation paired with a
brainpool512r1 ephemeral exchange") — computed the same way as an X3DH
leg (ECDH output concatenated with KEM shared secret, no additional
KDF wrapping before `KDF_RK` consumes it as IKM).

### 3.2 DH ratchet step

Triggered whenever a received message carries a new peer ratchet public
key (ECDH + KEM) not yet seen:

1. Using the incoming message's `previous_chain_length`, derive and
   cache (§5) every remaining message key on the *current*
   `receiving_chain` — from `state.receive_message_number` up to (but
   not including) `previous_chain_length` — before replacing that
   chain. This is what makes a message the sender sent right before
   ratcheting, but that arrives *after* their next-chain message,
   still decryptable: its key was cached here instead of being lost
   when `receiving_chain` gets overwritten in step 2.
2. `receiving_chain = KDF_RK(root_key, ECDH(self_ratchet_ecdh, peer_new_ratchet_ecdh) || KEM_decapsulate(self_ratchet_kem, peer's KEM ciphertext))`.
3. A fresh `self_ratchet_ecdh`/`self_ratchet_kem` keypair is generated.
4. `sending_chain = KDF_RK(root_key, ECDH(new self_ratchet_ecdh, peer_new_ratchet_ecdh) || fresh KEM encapsulation against peer's KEM public key)`.
5. `send_message_number` and `receive_message_number` reset to 0 for
   their respective new chains.

This is Signal's standard DH ratchet step, extended with the KEM leg
alongside the ECDH leg at every occurrence.

## 4. Message Encrypt/Decrypt

### 4.1 `encrypt_message(state: &mut RatchetState, plaintext: &[u8], aad: &[u8]) -> Result<RatchetMessage, RatchetError>`

1. If `state.sending_chain` is `None` (first message after a DH ratchet
   step we haven't sent on yet, or the very first message from an
   X3DH-derived `root_key`), perform the sending half of §3.2 step 2–4
   using a freshly generated ratchet keypair.
2. `(new_chain_key, message_key) = KDF_CK(sending_chain.chain_key)`; store
   `new_chain_key`, zeroize the old one.
3. Encrypt `plaintext` with `aegis_crypto::aead` (AES-256-GCM) under
   `message_key`, with `aad` passed through and the message header
   (below) also authenticated as associated data.
4. Increment `send_message_number`. Zeroize `message_key` after use.

### 4.2 `decrypt_message(state: &mut RatchetState, message: &RatchetMessage, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, RatchetError>`

1. If `message`'s header ratchet public keys differ from
   `state.peer_ratchet_ecdh_public`/`peer_ratchet_kem_public`, perform a
   DH ratchet step (§3.2) first.
2. If `message.message_number < state.receive_message_number`: look up
   `(header ratchet pubkey, message_number)` in the skipped-key cache
   (§5). Hit → decrypt and remove the entry. Miss → `RatchetError::UnknownMessage`
   (already-processed or evicted-past-the-bound message; never panics).
3. If `message.message_number > state.receive_message_number`: derive
   and cache (§5) each intervening message key via repeated `KDF_CK`
   calls, then derive the target key the same way.
4. Decrypt via `aegis_crypto::aead`. Authentication failure (tampered
   ciphertext, wrong key) → `RatchetError::DecryptionFailed`, never a
   panic — matches `aegis-crypto`'s existing fail-closed policy.
5. Zeroize the message key immediately after use (whether derived
   fresh or pulled from the skipped-key cache).

### 4.3 `RatchetMessage` wire format

```
RatchetMessage {
    header: RatchetHeader,
    ciphertext: Vec<u8>,   // length-prefixed: u32 big-endian length || bytes
}

RatchetHeader {
    ratchet_ecdh_public: [u8; 65],        // sender's current ratchet ECDH public key
    ratchet_kem_public: [u8; 1568],       // sender's current ML-KEM-1024 encapsulation
                                           // key — an "I'm listening on this" announcement,
                                           // always present, mirroring ratchet_ecdh_public
    kem_ciphertext: Option<[u8; 1568]>,   // see below — present iff first_message_on_new_chain
    message_number: u32,
    previous_chain_length: u32,           // §3.2 step 1: number of messages the OLD sending
                                           // chain reached before this ratchet step, so the
                                           // receiver knows exactly how many skipped keys to
                                           // derive from the old chain first — Signal's "PN"
}
```

KEM is asymmetric where ECDH is symmetric (both sides of a DH can
independently compute the same point from their own private key and
the other's public key; only the holder of a KEM ciphertext's matching
decapsulation key can recover its shared secret — encapsulation is a
one-way operation against a public key). This means the ratchet's KEM
leg cannot mirror `ratchet_ecdh_public`'s "both sides derive the same
value" pattern directly. Resolution: **every header carries the
sender's current KEM public key** (so the peer has something fresh to
encapsulate against once *they* next start a sending chain — this is
`ratchet_kem_public`, always present), and **`kem_ciphertext` is present
only on the first message of a newly started sending chain** — the
actual ciphertext the sender just encapsulated against the receiver's
most-recently-announced `ratchet_kem_public` (from the receiver's prior
message, or the pre-key bundle for the session's very first message),
which is exactly the KEM leg §3.1's `KDF_RK` call consumed for this
ratchet step. The receiver decapsulates that ciphertext with the
decapsulation key matching whichever public key they last announced.

## 5. Skipped-Message Key Cache

Adopts Signal's algorithm directly (see [Double Ratchet §2.6,
"Deferred key derivation"](https://signal.org/docs/specifications/doubleratchet/#deferring-key-derivation)):
a bounded map from `(sender_ratchet_ecdh_public, message_number)` to a
`Zeroizing` message key. Bound: **1000 entries** (Signal's own
`MAX_SKIP` default). Insertion past the bound evicts the
oldest-inserted entry (simple FIFO, not LRU — matches Signal's
reference behavior, no access-recency tracking needed). A lookup that
matches consumes (removes) the entry — each skipped key is single-use,
preserving forward secrecy for messages that do eventually arrive.

## 6. Error Handling

```rust
pub enum RatchetError {
    MalformedPreKeyBundle,
    InvalidBundleSignature,
    MalformedMessage,
    UnknownMessage,          // message_number below current, not in skipped-key cache
    DecryptionFailed,        // AEAD authentication failure
    SkippedKeyLimitExceeded, // would-be skip gap larger than MAX_SKIP in one jump
}
```

Matches `aegis-crypto`'s policy exactly: nothing in this crate panics
on attacker-controlled input (malformed bundles, malformed messages,
tampered ciphertext, adversarial message-number gaps). The only panic
path is fail-closed OS RNG failure during ephemeral key generation,
same as `aegis-crypto`.

## 7. Testing Strategy

No official KAT vectors exist for this protocol — it's a novel
combination of standardized primitives (ML-KEM-1024, brainpool512r1,
HKDF-SHA512, AES-256-GCM), not itself a standardized construction with
published test vectors. Correctness rests on:

- **Two-party agreement**: simulated Alice and Bob independently derive
  identical root keys from an X3DH handshake, and identical message
  keys at every ratchet step, without ever sharing state directly (only
  the wire-format bytes either side would actually transmit).
- **Per-function unit tests**: `KDF_RK`/`KDF_CK` determinism and
  distinctness (same inputs → same outputs; different inputs → different
  outputs — same style as `aegis-crypto`'s `kdf` tests), pre-key bundle
  signature verification (valid accepted, tampered rejected), wire
  format round-trips.
- **Protocol-level scenarios**: in-order conversation, out-of-order
  delivery (a message arrives after a later one), a long gap then
  catch-up (multiple skipped keys derived at once), skipped-key cache
  eviction past the 1000 bound (oldest becomes `UnknownMessage`),
  malformed/tampered input at each entry point (bundle, handshake
  message, ratchet message) rejected without panicking.
- **Zeroization**: message keys, chain keys, and ephemeral ratchet
  private keys are gone (checked via the same technique `aegis-crypto`'s
  existing zeroize tests use) after they go out of scope.
