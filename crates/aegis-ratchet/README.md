# aegis-ratchet

PQ-X3DH key agreement and a hybrid post-quantum/classical Double Ratchet
for [AegisPQC](https://github.com/Basty-devel/AEGIS), a post-quantum
secure messenger. Phase 1 of `AEGIS.Plan.V0.2.md` Section 3: pairwise
sessions only. Sender-keys groups (§3.1) and multi-device linking
(§3.2) are out of scope for this crate — each gets its own plan built
on top of the public API here.

> **NOT independently audited.** Do not rely on this code for
> life-critical communications until a third-party cryptographic audit
> has been completed.

## What this is

A pure, synchronous state machine — no I/O, no async, no network or
storage code. You hand it key material and bytes; it hands back key
material and bytes. Callers own transport, persistence, and prekey
bundle distribution.

1. **PQ-X3DH** ([`x3dh`]) — [Signal's X3DH](https://signal.org/docs/specifications/x3dh/)
   extended from a 3-DH combiner to a hybrid 4-leg one: three
   brainpoolP512r1 ECDH legs plus one or two ML-KEM-1024 encapsulations
   (a second KEM leg when the responder's one-time prekey is
   consumed), combined via `aegis_crypto`'s domain-separated
   `derive_key` under a protocol label distinct from
   `aegis_crypto::hybrid`'s own. [`x3dh::initiate_x3dh`] /
   [`x3dh::respond_to_x3dh`] run the two sides; both are covered by
   two-party agreement tests asserting byte-identical IKM leg
   ordering.
2. **Double Ratchet** ([`state`]) — [Signal's Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
   adapted for hybrid rekeying: every DH ratchet step injects a fresh
   ML-KEM-1024 + brainpool512r1 pair, `KDF_RK`/`KDF_CK` are
   HMAC-SHA512-based ([`kdf_chain`]), and a skipped-message-key cache
   (1000-entry FIFO bound, matching Signal's reference `MAX_SKIP`)
   absorbs out-of-order delivery. [`state::RatchetState::encrypt`] /
   [`state::RatchetState::decrypt`] are the whole runtime surface once
   a session exists.
3. **Prekey bundles** ([`prekey`]) — identity, signed-prekey, and
   one-time-prekey types and their wire encoding, plus the signature
   checks a responder's bundle must pass before any DH computation
   trusts it (`verify_signed_pre_key`, `verify_identity_ecdh_binding`).

| Module | Contents |
|---|---|
| [`x3dh`](src/x3dh.rs) | `initiate_x3dh`, `respond_to_x3dh`, `X3DHPreamble` |
| [`state`](src/state.rs) | `RatchetState` (`from_x3dh_initiator`/`_responder`, `encrypt`, `decrypt`, `to_bytes`/`from_bytes`), `RatchetHeader`, `RatchetMessage` |
| [`prekey`](src/prekey.rs) | `IdentityKeyPair`, `IdentityKeys`, `SignedPreKey`, `OneTimePreKey`, `PreKeyBundle`, `DualVerifyingKey` |
| [`kdf_chain`](src/kdf_chain.rs) | `kdf_rk`, `kdf_ck` — the ratchet's own HMAC-SHA512 root/chain KDFs |
| [`error`](src/error.rs) | `RatchetError` |

## Session state is opaque bytes

`RatchetState`'s fields are all crate-private. Callers only ever see
[`state::RatchetState::to_bytes`] / [`state::RatchetState::from_bytes`]
— a session is a blob you store and reload, not a struct you inspect
or construct by hand. `to_bytes` returns `Zeroizing<Vec<u8>>` and
covers every field, including the skipped-message-key cache, in a
deterministic order.

## Transactional ratchet steps

A DH ratchet step is planned and committed separately:
[`state::RatchetState::plan_dh_ratchet_step`] takes `&self` and cannot
mutate the session; the resulting `PendingRatchetStep` is only applied
by [`state::RatchetState::commit_dh_ratchet_step`] after `decrypt` has
confirmed the triggering message's AEAD tag. A replayed, forged, or
header-tampered message that fails decryption leaves the session
byte-for-byte unchanged rather than silently advancing keys or losing
buffered skipped keys — this is enforced by the type system, not by
caller discipline.

## Memory zeroization

Every secret `aegis-ratchet` produces or holds — root keys, chain
keys, message keys, ephemeral DH/KEM private material, and pending
ratchet-step state that gets dropped unused — is either
`zeroize::Zeroizing` or a key type that wipes itself on drop,
consistent with [`aegis-crypto`](https://crates.io/crates/aegis-crypto)'s
own zeroization discipline (see that crate's README for what this
guarantee does and does not cover).

## Error handling

Peer-controlled input — prekey bundles, signatures, ratchet headers,
ciphertexts — never panics this crate; malformed or invalid input
returns [`error::RatchetError`]. `RatchetError` is `#[non_exhaustive]`
and wraps `aegis_crypto::CryptoError` via `From` for primitive-level
failures.

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for noncommercial use;
commercial use requires a separate license.
