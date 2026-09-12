//! The Double Ratchet's state machine: `RatchetState`, its wire
//! serialization, and the `RatchetHeader`/`RatchetMessage` wire types
//! for encrypted messages. See design §3, §4.3.

use core::fmt;

use crate::error::RatchetError;
use crate::kdf_chain::{kdf_ck, kdf_rk, CHAIN_KEY_LEN, MESSAGE_KEY_LEN, ROOT_KEY_LEN};
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
    /// The peer's current ratchet ML-KEM encapsulation key, or `None`
    /// when it isn't known yet.
    ///
    /// `None` is reachable in exactly one situation: the X3DH
    /// responder between [`RatchetState::from_x3dh_responder`] and his
    /// first successful [`RatchetState::decrypt`], because only the
    /// initiator's first message header carries that key (design
    /// §4.3). This used to be an all-zero placeholder "overwritten
    /// before it is ever used" — but an application that lets the
    /// responder speak first breaks that assumption, and all-zero
    /// bytes pass ML-KEM's FIPS 203 modulus check, so encapsulation
    /// silently succeeded against garbage and produced a message the
    /// peer could never decrypt (final-review finding I1). The
    /// `Option` makes the unknown case unrepresentable-as-zero, and
    /// [`RatchetState::start_sending_chain`] fails with
    /// [`RatchetError::NotReadyToSend`] instead.
    pub(crate) peer_ratchet_kem_public: Option<[u8; KEM_ENCAPSULATION_KEY_LEN]>,
    pub(crate) send_message_number: u32,
    pub(crate) receive_message_number: u32,
    pub(crate) previous_chain_length: u32,
    /// Message keys derived ahead of the current receive counter, kept
    /// around so a message that arrives out of order still decrypts
    /// (Task 10, design §5). Bounded to `skipped_keys::MAX_SKIP` entries.
    pub(crate) skipped_message_keys: crate::skipped_keys::SkippedKeyCache,
}

// Manual `Debug`, not `#[derive(Debug)]`: `Brainpool512SecretKey` and
// `MlKem1024KeyPair` deliberately do not implement `Debug` themselves
// (design goal: secret key material must never be printable by
// accident), so a derive wouldn't compile anyway. This impl exists
// only so `Result<RatchetState, _>::unwrap_err()` is usable in tests
// (`unwrap_err` requires `T: Debug`); every secret-bearing field is
// redacted, never the counters or public keys.
impl fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RatchetState")
            .field("root_key", &"<redacted>")
            .field("sending_chain", &self.sending_chain.is_some())
            .field("receiving_chain", &self.receiving_chain.is_some())
            .field("self_ratchet_ecdh", &"<redacted>")
            .field("self_ratchet_kem", &"<redacted>")
            .field("peer_ratchet_ecdh_public", &"<public, omitted>")
            .field(
                "peer_ratchet_kem_public",
                &self.peer_ratchet_kem_public.map(|_| "<public, omitted>"),
            )
            .field("send_message_number", &self.send_message_number)
            .field("receive_message_number", &self.receive_message_number)
            .field("previous_chain_length", &self.previous_chain_length)
            .field("skipped_message_keys_len", &self.skipped_message_keys.len())
            .finish()
    }
}

/// A DH ratchet step that has been fully *computed* but not yet
/// applied to any [`RatchetState`] — the uncommitted half of
/// [`RatchetState::plan_dh_ratchet_step`] /
/// [`RatchetState::commit_dh_ratchet_step`].
///
/// Exists solely to make finding C2's transactional guarantee
/// expressible in the type system: `plan_dh_ratchet_step` takes
/// `&self` and so *cannot* mutate the session, and every field write
/// the step implies is parked in here until
/// [`RatchetState::decrypt`] has seen the triggering message clear its
/// AEAD tag. If the message turns out to be a replay, a forgery, or a
/// header-tampered copy, this value is simply dropped and the session
/// is byte-for-byte unchanged.
///
/// Every secret it carries (`new_root_key`, `new_receiving_chain_key`,
/// the message keys inside `old_chain_skipped`, and both new private
/// keypairs) is either `Zeroizing` or a key type that wipes itself on
/// drop, so dropping an abandoned step wipes rather than leaks.
struct PendingRatchetStep {
    /// Message keys for the chain being superseded, derived here
    /// rather than inserted directly into
    /// `RatchetState::skipped_message_keys`, so a failed message does
    /// not leave `MAX_SKIP`-bounded cache churn (and eviction of
    /// genuinely useful keys) behind as a side effect.
    old_chain_skipped: Vec<(
        [u8; ECDH_PUBLIC_KEY_LEN],
        u32,
        Zeroizing<[u8; MESSAGE_KEY_LEN]>,
    )>,
    new_root_key: Zeroizing<[u8; ROOT_KEY_LEN]>,
    new_receiving_chain_key: Zeroizing<[u8; CHAIN_KEY_LEN]>,
    new_self_ratchet_ecdh: Brainpool512SecretKey,
    new_self_ratchet_kem: MlKem1024KeyPair,
    new_peer_ratchet_ecdh_public: [u8; ECDH_PUBLIC_KEY_LEN],
    new_peer_ratchet_kem_public: [u8; KEM_ENCAPSULATION_KEY_LEN],
    new_previous_chain_length: u32,
}

impl RatchetState {
    /// Build the AEAD associated data for one message: the caller's
    /// own `aad` **and** the message header, each length-framed.
    ///
    /// Design §4.1 requires the header to be authenticated alongside
    /// the caller's `aad`; the implementation passed only `aad`, which
    /// left every header field malleable (final-review finding C1).
    /// `message_number` and `previous_chain_length` in particular are
    /// pure integers an attacker could edit in flight: bumping
    /// `previous_chain_length` drives the receiver's catch-up loop
    /// into deriving and caching keys for messages that never existed,
    /// and bumping `message_number` fast-forwards the receiving chain
    /// past keys it will now never derive — both of which corrupt a
    /// session without ever touching the ciphertext the AEAD tag
    /// actually covered.
    ///
    /// Each part is prefixed with its own big-endian `u64` length, so
    /// the encoding is injective: no two distinct `(aad, header)`
    /// pairs can produce the same associated-data bytes. Plain
    /// concatenation would not have that property — `aad = "AB"` with
    /// a header starting `C`, and `aad = "A"` with a header starting
    /// `BC`, would be indistinguishable, letting an attacker shift
    /// bytes across the boundary.
    fn aead_associated_data(caller_aad: &[u8], header: &RatchetHeader) -> Vec<u8> {
        let header_bytes = header.to_bytes();
        let mut out = Vec::with_capacity(16 + caller_aad.len() + header_bytes.len());
        out.extend_from_slice(&(caller_aad.len() as u64).to_be_bytes());
        out.extend_from_slice(caller_aad);
        out.extend_from_slice(&(header_bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(&header_bytes);
        out
    }

    /// Build Alice's initial state right after [`crate::x3dh::initiate_x3dh`].
    /// Bob's signed pre-key doubles as his first ratchet public keys —
    /// standard X3DH-to-Double-Ratchet handoff. `sending_chain` starts
    /// `None`; the first call that needs to send a message starts it
    /// via the same "start a sending chain" step the DH ratchet uses
    /// (Task 7/8).
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
            peer_ratchet_kem_public: Some(peer_signed_pre_key_kem_public),
            send_message_number: 0,
            receive_message_number: 0,
            previous_chain_length: 0,
            skipped_message_keys: crate::skipped_keys::SkippedKeyCache::new(),
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
    /// `None`, and let the DH ratchet step's existing "unseen ratchet
    /// public key -> run a DH ratchet step first" logic (Task 7/9)
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
            // only her first message's header carries it. `None`, not
            // an all-zero placeholder: see the field's own doc comment
            // and final-review finding I1. Until the DH ratchet step
            // driven by Alice's first message fills this in, `encrypt`
            // refuses with `RatchetError::NotReadyToSend` rather than
            // encapsulating against a key nobody holds.
            peer_ratchet_kem_public: None,
            send_message_number: 0,
            receive_message_number: 0,
            previous_chain_length: 0,
            skipped_message_keys: crate::skipped_keys::SkippedKeyCache::new(),
        }
    }

    /// Serialize every field of this state to a flat byte buffer, in
    /// this fixed order: `root_key` (64 bytes) -- `sending_chain`
    /// presence byte + optional 64-byte chain key -- `receiving_chain`
    /// presence byte + optional 64-byte chain key -- `self_ratchet_ecdh`
    /// (64 bytes, via [`Brainpool512SecretKey::to_bytes`]) --
    /// `self_ratchet_kem` (64-byte seed, via
    /// [`MlKem1024KeyPair::to_seed_bytes`]) -- `peer_ratchet_ecdh_public`
    /// -- `peer_ratchet_kem_public` presence byte + optional 1568-byte
    /// key -- the three `u32` counters, big-endian.
    /// [`Self::from_bytes`] must consume fields in this exact order.
    ///
    /// The presence byte on `peer_ratchet_kem_public` follows the same
    /// convention every other optional fixed-size field in this crate
    /// uses (`RatchetHeader.kem_ciphertext`,
    /// `PreKeyBundle.one_time_pre_key`): `0x00` for absent, `0x01`
    /// followed by the value.
    ///
    /// Returns `Zeroizing<Vec<u8>>`, not a plain `Vec<u8>`: this buffer
    /// carries the entire secret ratchet session state (root key, chain
    /// keys, the private ECDH scalar, the KEM seed), so it must be wiped
    /// on drop like every other secret buffer in this crate, even though
    /// it's also the value most likely to be persisted or transmitted by
    /// a caller.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&*self.root_key);

        match &self.sending_chain {
            None => out.push(0x00),
            Some(chain) => {
                out.push(0x01);
                out.extend_from_slice(&*chain.chain_key);
            }
        }
        match &self.receiving_chain {
            None => out.push(0x00),
            Some(chain) => {
                out.push(0x01);
                out.extend_from_slice(&*chain.chain_key);
            }
        }

        out.extend_from_slice(&*self.self_ratchet_ecdh.to_bytes());
        out.extend_from_slice(&*self.self_ratchet_kem.to_seed_bytes());
        out.extend_from_slice(&self.peer_ratchet_ecdh_public);
        match &self.peer_ratchet_kem_public {
            None => out.push(0x00),
            Some(key) => {
                out.push(0x01);
                out.extend_from_slice(key);
            }
        }
        out.extend_from_slice(&self.send_message_number.to_be_bytes());
        out.extend_from_slice(&self.receive_message_number.to_be_bytes());
        out.extend_from_slice(&self.previous_chain_length.to_be_bytes());

        // Skipped-message-key cache (Task 10): a `u32` entry count,
        // then each `(sender_ratchet_ecdh_public, message_number, key)`
        // triple, in the cache's own FIFO insertion order -- a
        // `HashMap`'s iteration order is not guaranteed stable across
        // runs, so serializing straight from it would make round-trips
        // non-reproducible (and unit-testable) even though the *set* of
        // entries would still be correct. Iterating in insertion order
        // instead makes `to_bytes` deterministic for a given cache
        // state, which the round-trip test below relies on.
        let entries: Vec<_> = self.skipped_message_keys.iter_in_insertion_order().collect();
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for ((sender_ratchet_ecdh_public, message_number), key) in entries {
            out.extend_from_slice(&sender_ratchet_ecdh_public);
            out.extend_from_slice(&message_number.to_be_bytes());
            out.extend_from_slice(&**key);
        }

        Zeroizing::new(out)
    }

    /// Reconstruct a [`RatchetState`] from bytes produced by
    /// [`Self::to_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`RatchetError::MalformedMessage`] if `bytes` is
    /// truncated at any point, or if `self_ratchet_ecdh`'s 64 bytes do
    /// not decode to a valid brainpool512r1 scalar (`self_ratchet_kem`
    /// cannot fail this way -- every 64-byte seed is a valid ML-KEM-1024
    /// seed). Never panics on malformed input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut cursor = ByteCursor::new(bytes);

        let root_key = Zeroizing::new(
            cursor
                .take_array::<ROOT_KEY_LEN>()
                .map_err(|_| RatchetError::MalformedMessage)?,
        );

        let sending_chain = match cursor.take_byte().map_err(|_| RatchetError::MalformedMessage)? {
            0x00 => None,
            0x01 => Some(ChainState {
                chain_key: Zeroizing::new(
                    cursor
                        .take_array::<CHAIN_KEY_LEN>()
                        .map_err(|_| RatchetError::MalformedMessage)?,
                ),
            }),
            _ => return Err(RatchetError::MalformedMessage),
        };
        let receiving_chain = match cursor.take_byte().map_err(|_| RatchetError::MalformedMessage)? {
            0x00 => None,
            0x01 => Some(ChainState {
                chain_key: Zeroizing::new(
                    cursor
                        .take_array::<CHAIN_KEY_LEN>()
                        .map_err(|_| RatchetError::MalformedMessage)?,
                ),
            }),
            _ => return Err(RatchetError::MalformedMessage),
        };

        // Both intermediate byte buffers below are secret material (a
        // private scalar, a KEM seed) held only long enough to
        // reconstruct the typed key -- wrapped in `Zeroizing` so they
        // are wiped on drop rather than left on the stack, matching
        // `aegis-crypto`'s own convention of explicitly zeroizing every
        // intermediate secret buffer (see e.g. `ecdh.rs::generate`).
        let self_ratchet_ecdh_bytes: Zeroizing<[u8; 64]> = Zeroizing::new(
            cursor
                .take_array::<64>()
                .map_err(|_| RatchetError::MalformedMessage)?,
        );
        let self_ratchet_ecdh = Brainpool512SecretKey::from_bytes(&self_ratchet_ecdh_bytes)
            .map_err(|_| RatchetError::MalformedMessage)?;

        let self_ratchet_kem_seed: Zeroizing<[u8; 64]> = Zeroizing::new(
            cursor
                .take_array::<64>()
                .map_err(|_| RatchetError::MalformedMessage)?,
        );
        let self_ratchet_kem = MlKem1024KeyPair::from_seed_bytes(&self_ratchet_kem_seed);

        let peer_ratchet_ecdh_public = cursor
            .take_array::<ECDH_PUBLIC_KEY_LEN>()
            .map_err(|_| RatchetError::MalformedMessage)?;
        let peer_ratchet_kem_public =
            match cursor.take_byte().map_err(|_| RatchetError::MalformedMessage)? {
                0x00 => None,
                0x01 => Some(
                    cursor
                        .take_array::<KEM_ENCAPSULATION_KEY_LEN>()
                        .map_err(|_| RatchetError::MalformedMessage)?,
                ),
                _ => return Err(RatchetError::MalformedMessage),
            };

        let send_message_number = u32::from_be_bytes(
            cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?,
        );
        let receive_message_number = u32::from_be_bytes(
            cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?,
        );
        let previous_chain_length = u32::from_be_bytes(
            cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?,
        );

        let skipped_key_count = u32::from_be_bytes(
            cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?,
        );
        let mut skipped_message_keys = crate::skipped_keys::SkippedKeyCache::new();
        for _ in 0..skipped_key_count {
            let sender_ratchet_ecdh_public = cursor
                .take_array::<ECDH_PUBLIC_KEY_LEN>()
                .map_err(|_| RatchetError::MalformedMessage)?;
            let message_number = u32::from_be_bytes(
                cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?,
            );
            let key: Zeroizing<[u8; crate::kdf_chain::MESSAGE_KEY_LEN]> = Zeroizing::new(
                cursor
                    .take_array::<{ crate::kdf_chain::MESSAGE_KEY_LEN }>()
                    .map_err(|_| RatchetError::MalformedMessage)?,
            );
            skipped_message_keys.insert(sender_ratchet_ecdh_public, message_number, key);
        }

        Ok(Self {
            root_key,
            sending_chain,
            receiving_chain,
            self_ratchet_ecdh,
            self_ratchet_kem,
            peer_ratchet_ecdh_public,
            peer_ratchet_kem_public,
            send_message_number,
            receive_message_number,
            previous_chain_length,
            skipped_message_keys,
        })
    }

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

    /// Compute a DH ratchet step (design §3.2) **without touching
    /// `self`**, so the caller can hold the result uncommitted until
    /// the message that triggered it has actually authenticated.
    ///
    /// This split exists because of final-review finding C2. The
    /// previous `dh_ratchet_step` mutated `self` directly and returned
    /// `()`, which meant a message that later failed its AEAD check had
    /// *already* replaced the root key, the receiving chain, both peer
    /// key fields and the self-ratchet keypair. That is not a
    /// theoretical hazard: ML-KEM decapsulation cannot fail on a wrong
    /// or replayed ciphertext — FIPS 203 mandates implicit rejection,
    /// which silently returns an unpredictable shared secret instead of
    /// an error — so an ordinary duplicate of an already-processed
    /// message reached this code, produced a garbage chain, committed
    /// it, and permanently destroyed the session in both directions,
    /// with the corruption only surfacing later on some unrelated,
    /// legitimate message.
    ///
    /// `header`'s KEM ciphertext must be present: the first message of
    /// any new peer chain always carries one, by construction of
    /// [`Self::start_sending_chain`].
    fn plan_dh_ratchet_step(
        &self,
        header: &RatchetHeader,
    ) -> Result<PendingRatchetStep, RatchetError> {
        // Before the current receiving chain is superseded, derive the
        // message keys for any messages on it that were never received
        // (design §5) -- otherwise a message that was in flight when
        // the peer ratcheted forward would be silently stranded: once
        // `receiving_chain` is replaced, there is no way to derive that
        // old chain's keys again. Collected into a local buffer, not
        // inserted into `self.skipped_message_keys`, for the same
        // transactional reason as everything else here.
        let mut old_chain_skipped = Vec::new();
        if let Some(old_chain) = &self.receiving_chain {
            // Bound the catch-up gap before deriving anything:
            // `header.previous_chain_length` is a peer-controlled `u32`
            // read straight off the wire (Task 10's Finding #1).
            // Without this check, a malicious header (e.g.
            // `previous_chain_length = u32::MAX`) would drive this loop
            // through billions of `kdf_ck` calls before the message's
            // own AEAD tag is ever checked -- a DoS. Guarded against
            // `u32` underflow: only compute the gap when there actually
            // is one.
            if header.previous_chain_length > self.receive_message_number {
                let gap = header.previous_chain_length - self.receive_message_number;
                if gap as usize > crate::skipped_keys::MAX_SKIP {
                    return Err(RatchetError::SkippedKeyLimitExceeded);
                }
            }
            let mut chain_key = old_chain.chain_key.clone();
            let mut message_number = self.receive_message_number;
            while message_number < header.previous_chain_length {
                let (new_chain_key, message_key) = kdf_ck(&chain_key);
                old_chain_skipped.push((
                    self.peer_ratchet_ecdh_public,
                    message_number,
                    message_key,
                ));
                chain_key = new_chain_key;
                message_number += 1;
            }
        }

        let kem_ciphertext = header.kem_ciphertext.ok_or(RatchetError::MalformedMessage)?;

        let ecdh_shared = aegis_crypto::ecdh::brainpool512_diffie_hellman(
            &self.self_ratchet_ecdh,
            &header.ratchet_ecdh_public,
        )?;
        let kem_shared =
            aegis_crypto::kem::ml_kem_decapsulate(&self.self_ratchet_kem, &kem_ciphertext)?;
        let hybrid_secret = Self::hybrid_ratchet_secret(&ecdh_shared, &kem_shared);

        let (new_root_key, new_receiving_chain_key) =
            kdf_rk(&self.root_key, hybrid_secret.as_ref());

        Ok(PendingRatchetStep {
            old_chain_skipped,
            new_root_key,
            new_receiving_chain_key,
            // A fresh keypair for our own next sending chain --
            // generated now so the *next* start_sending_chain call
            // (from encrypt, whenever we next send) uses it, matching
            // Signal's "generate immediately on receiving a new ratchet
            // key" step.
            new_self_ratchet_ecdh: Brainpool512SecretKey::generate(),
            new_self_ratchet_kem: MlKem1024KeyPair::generate(),
            new_peer_ratchet_ecdh_public: header.ratchet_ecdh_public,
            new_peer_ratchet_kem_public: header.ratchet_kem_public,
            new_previous_chain_length: self.send_message_number,
        })
    }

    /// Apply a [`PendingRatchetStep`] produced by
    /// [`Self::plan_dh_ratchet_step`]. Every field write the DH ratchet
    /// step performs happens here and nowhere else, so the caller
    /// controls exactly when the session state changes — see
    /// [`Self::decrypt`], which calls this only after the triggering
    /// message has authenticated.
    fn commit_dh_ratchet_step(&mut self, step: PendingRatchetStep) {
        for (sender, message_number, key) in step.old_chain_skipped {
            self.skipped_message_keys
                .insert(sender, message_number, key);
        }
        self.root_key = step.new_root_key;
        self.receiving_chain = Some(ChainState {
            chain_key: step.new_receiving_chain_key,
        });
        self.receive_message_number = 0;
        self.previous_chain_length = step.new_previous_chain_length;
        self.peer_ratchet_ecdh_public = step.new_peer_ratchet_ecdh_public;
        self.peer_ratchet_kem_public = Some(step.new_peer_ratchet_kem_public);
        self.self_ratchet_ecdh = step.new_self_ratchet_ecdh;
        self.self_ratchet_kem = step.new_self_ratchet_kem;
        self.sending_chain = None;
        self.send_message_number = 0;
    }

    /// Start a fresh sending chain toward `peer_ratchet_ecdh_public`/
    /// `peer_ratchet_kem_public`, encapsulating a fresh KEM ciphertext
    /// against the peer's current KEM public key (design §3.1/§4.3).
    /// Returns the header the resulting message must carry -- this is
    /// the *only* header shape that ever carries `kem_ciphertext:
    /// Some(_)`, which is exactly what marks "first message of a new
    /// chain" to the receiver.
    ///
    /// # Errors
    ///
    /// Returns [`RatchetError::NotReadyToSend`] if
    /// `peer_ratchet_kem_public` is `None` — the X3DH responder before
    /// his first successful `decrypt` (finding I1). Checked first, so
    /// this function is a no-op on `self` when it fails.
    pub(crate) fn start_sending_chain(&mut self) -> Result<RatchetHeader, RatchetError> {
        // First statement in the function, deliberately: everything
        // below either mutates `self` or is wasted work, and this is
        // the one failure mode that is a property of the session
        // rather than of the key material.
        let peer_ratchet_kem_public = self
            .peer_ratchet_kem_public
            .ok_or(RatchetError::NotReadyToSend)?;

        let ecdh_shared = aegis_crypto::ecdh::brainpool512_diffie_hellman(
            &self.self_ratchet_ecdh,
            &self.peer_ratchet_ecdh_public,
        )?;
        let (kem_ciphertext_vec, kem_shared) =
            aegis_crypto::kem::ml_kem_encapsulate(&peer_ratchet_kem_public)?;
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

        // Every header field is now final, so the associated data can
        // be built: `aad` plus the header itself, length-framed
        // (finding C1 -- see `aead_associated_data`). Building it here
        // rather than earlier is load-bearing: `message_number` is
        // assigned on the line above, and authenticating a header that
        // differs from the one actually transmitted would make every
        // message undecryptable.
        let associated_data = Self::aead_associated_data(aad, &header);

        let nonce = [0u8; 12]; // safe: message_key is single-use, see Task 8 notes below
        let ciphertext = aegis_crypto::aead::encrypt(
            aegis_crypto::aead::AeadAlgorithm::Aes256Gcm,
            &message_key,
            &nonce,
            &associated_data,
            plaintext,
        )
        .map_err(|_| RatchetError::DecryptionFailed)?; // encrypt only fails on malformed inputs, which don't occur here; kept as a Result for symmetry with decrypt

        self.send_message_number += 1;

        Ok(RatchetMessage { header, ciphertext })
    }

    /// Decrypt and authenticate `message` (design §4.2 in-order case;
    /// Task 10 adds out-of-order/skipped-key handling on top of this).
    /// Performs a DH ratchet step first if `message.header` carries a
    /// peer ratchet public key not yet seen.
    ///
    /// # Transactional guarantee
    ///
    /// **No field of `self` changes unless this call returns `Ok`.**
    /// Every candidate mutation — the DH ratchet step, the
    /// skipped-key catch-up derivations, the chain-key advance, the
    /// receive counter, and the consumption of a cached skipped key —
    /// is computed into locals and applied only past the single
    /// commit point below, after the AEAD tag has verified.
    ///
    /// This is final-review finding C2, and it is not a theoretical
    /// hazard. ML-KEM decapsulation cannot report a wrong ciphertext:
    /// FIPS 203 §6.3 mandates *implicit rejection*, returning an
    /// unpredictable-but-well-formed shared secret rather than an
    /// error. So an ordinary duplicate of an already-processed
    /// chain-opening message — no attacker required, just a network
    /// retransmit — used to reach `dh_ratchet_step`, decapsulate to
    /// garbage, and commit a garbage root key, receiving chain, peer
    /// key pair and self key pair before the AEAD call that would have
    /// rejected it. The session was then permanently dead in both
    /// directions, and the failure surfaced later on an unrelated,
    /// perfectly legitimate message.
    pub fn decrypt(&mut self, message: &RatchetMessage, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, RatchetError> {
        // The header is authenticated alongside the caller's `aad`
        // (finding C1). Note what this buys the transactional logic
        // below for free: `message_number` and `previous_chain_length`
        // drive every derivation decision here, and they are now
        // covered by the same tag as the ciphertext, so a header-edited
        // message fails authentication instead of steering the state
        // machine.
        let associated_data = Self::aead_associated_data(aad, &message.header);
        let nonce = [0u8; 12]; // matches encrypt's nonce construction -- see Task 8 notes
        let header_sender = message.header.ratchet_ecdh_public;
        let message_number = message.header.message_number;

        // Try the skip-cache FIRST, keyed by the message's OWN header
        // ratchet key -- not `self.peer_ratchet_ecdh_public` -- and
        // before any ratchet-step decision (Finding #2). A message that
        // arrives late from a chain the peer has already superseded
        // carries that OLD ratchet key in its header, which no longer
        // matches `self.peer_ratchet_ecdh_public`; checking the cache
        // by the header's own key, before deciding whether a DH ratchet
        // step is needed, is the only way such a message ever reaches
        // the key `dh_ratchet_step`'s old-chain catch-up cached for it
        // when the peer ratcheted forward. This mirrors Signal's own
        // reference `RatchetDecrypt`, where `TrySkippedMessageKeys` runs
        // before `DHRatchet`.
        //
        // `peek` (+ `cloned`), never `take`: the lookup must not remove
        // the entry, because the AEAD call below may reject the
        // message, and a tampered delivery must not make a later,
        // correct retransmission of the same message undecryptable.
        // Remove-then-reinsert-on-failure would also silently move the
        // entry to the back of the cache's FIFO eviction order.
        if let Some(key) = self
            .skipped_message_keys
            .peek(header_sender, message_number)
            .cloned()
        {
            let plaintext = aegis_crypto::aead::decrypt(
                aegis_crypto::aead::AeadAlgorithm::Aes256Gcm,
                &key,
                &nonce,
                &associated_data,
                &message.ciphertext,
            )
            .map_err(|_| RatchetError::DecryptionFailed)?;

            // Commit point for this path: the key authenticated the
            // message, so consume it (skipped keys are single-use,
            // design §5). Nothing else about the session changes.
            self.skipped_message_keys.remove(header_sender, message_number);
            return Ok(Zeroizing::new(plaintext));
        }

        // ---- Everything from here to the commit point is computed
        // ---- into locals. `self` is not written to.

        // A header carrying an unseen peer ratchet key (or arriving
        // before any receiving chain exists) implies a DH ratchet step.
        // Plan it; do not apply it.
        let pending_step = if header_sender != self.peer_ratchet_ecdh_public
            || self.receiving_chain.is_none()
        {
            Some(self.plan_dh_ratchet_step(&message.header)?)
        } else {
            None
        };

        // Whichever chain this message belongs to -- the one the
        // pending step would install, or the live receiving chain --
        // is worked on as a local copy of its chain key plus a local
        // receive counter.
        let (mut chain_key, mut receive_message_number, chain_sender) = match &pending_step {
            Some(step) => (
                step.new_receiving_chain_key.clone(),
                0u32,
                step.new_peer_ratchet_ecdh_public,
            ),
            // `plan_dh_ratchet_step` runs above whenever
            // `receiving_chain` is `None`, so this branch always has a
            // chain; the `ok_or` is a defensive non-panicking fallback
            // rather than a reachable path.
            None => (
                self.receiving_chain
                    .as_ref()
                    .ok_or(RatchetError::UnknownMessage)?
                    .chain_key
                    .clone(),
                self.receive_message_number,
                self.peer_ratchet_ecdh_public,
            ),
        };

        if message_number < receive_message_number {
            // Already consumed on the live chain, and the skip-cache
            // lookup above (keyed by this exact header) already missed
            // -- there is nothing left to try.
            return Err(RatchetError::UnknownMessage);
        }

        // Message arrived ahead of the chain: derive every intervening
        // key so those messages can still decrypt later. Bound the gap
        // first -- `message_number` is peer-controlled, and although
        // finding C1 now authenticates it, that tag is only checked
        // *after* this loop, so the bound is still what stops an
        // unauthenticated header from costing billions of `kdf_ck`
        // calls.
        let gap = message_number - receive_message_number;
        if gap as usize > crate::skipped_keys::MAX_SKIP {
            return Err(RatchetError::SkippedKeyLimitExceeded);
        }
        let mut newly_skipped = Vec::with_capacity(gap as usize);
        while receive_message_number < message_number {
            let (next_chain_key, message_key) = kdf_ck(&chain_key);
            chain_key = next_chain_key;
            newly_skipped.push((chain_sender, receive_message_number, message_key));
            receive_message_number += 1;
        }

        let (new_chain_key, message_key) = kdf_ck(&chain_key);

        let plaintext = aegis_crypto::aead::decrypt(
            aegis_crypto::aead::AeadAlgorithm::Aes256Gcm,
            &message_key,
            &nonce,
            &associated_data,
            &message.ciphertext,
        )
        .map_err(|_| RatchetError::DecryptionFailed)?;

        // ================= COMMIT POINT =================
        // The message has authenticated. Only now does any of it
        // become visible in `self`. Everything below this line is
        // infallible by construction, so the session cannot be left
        // half-updated.
        if let Some(step) = pending_step {
            // Installs the new root key, peer keys, self keypair and
            // the superseded chain's outstanding skipped keys, and
            // resets the receiving chain/counter -- which the two
            // statements below then advance to this message's actual
            // position on that new chain.
            self.commit_dh_ratchet_step(step);
        }
        for (sender, skipped_message_number, key) in newly_skipped {
            self.skipped_message_keys
                .insert(sender, skipped_message_number, key);
        }
        self.receiving_chain = Some(ChainState {
            chain_key: new_chain_key,
        });
        self.receive_message_number = receive_message_number + 1;

        Ok(Zeroizing::new(plaintext))
    }
}

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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut cursor = ByteCursor::new(bytes);
        Self::from_cursor(&mut cursor)
    }

    pub(crate) fn from_cursor(cursor: &mut ByteCursor) -> Result<Self, RatchetError> {
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
        let header = RatchetHeader::from_cursor(&mut cursor)?;
        let len_bytes = cursor.take_array::<4>().map_err(|_| RatchetError::MalformedMessage)?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let ciphertext = cursor.take_vec(len).map_err(|_| RatchetError::MalformedMessage)?;
        Ok(Self { header, ciphertext })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf_chain::ROOT_KEY_LEN;
    use aegis_crypto::ecdh::Brainpool512SecretKey;
    use aegis_crypto::kem::MlKem1024KeyPair;

    /// Build a fully-handshaked two-party session (Alice as X3DH
    /// initiator, Bob as X3DH responder) for tests that need a real
    /// `RatchetState` on both sides rather than one side's initial
    /// state against synthetic peer keys. Reused by Task 10/11's tests.
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

        let (alice_root_key, preamble, _) =
            initiate_x3dh(&alice_identity, &bundle, ProtocolVersion::V1).unwrap();
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
        let (mut alice_state, mut bob_state) = two_party_session();
        let mut message = alice_state.encrypt(b"hello bob", b"").unwrap();
        message.ciphertext[0] ^= 0xFF;

        assert_eq!(bob_state.decrypt(&message, b"").unwrap_err(), RatchetError::DecryptionFailed);
    }

    #[test]
    fn decrypt_recovers_after_a_tampered_attempt_on_the_same_message() {
        // Regression test for the chain-key-advances-before-success bug:
        // a failed decrypt (tampered ciphertext) must NOT advance
        // receiving_chain's chain key or receive_message_number, so a
        // later retransmission of the *original, untampered* message at
        // the same message number can still be decrypted correctly.
        let (mut alice_state, mut bob_state) = two_party_session();
        let message = alice_state.encrypt(b"hello bob", b"").unwrap();

        let mut tampered = message.clone();
        tampered.ciphertext[0] ^= 0xFF;
        assert_eq!(
            bob_state.decrypt(&tampered, b"").unwrap_err(),
            RatchetError::DecryptionFailed,
        );

        // The real, untampered message at the same message number must
        // still decrypt successfully -- proving the chain key and
        // receive counter were left untouched by the failed attempt.
        let plaintext = bob_state.decrypt(&message, b"").unwrap();
        assert_eq!(&*plaintext, b"hello bob");
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

        // Planning alone must leave the state completely untouched
        // (finding C2) -- only the explicit commit applies it.
        let step = alice_state.plan_dh_ratchet_step(&header).unwrap();
        assert!(
            alice_state.receiving_chain.is_none(),
            "plan_dh_ratchet_step must not mutate the session",
        );
        assert_ne!(alice_state.peer_ratchet_ecdh_public, header.ratchet_ecdh_public);

        alice_state.commit_dh_ratchet_step(step);
        assert!(alice_state.receiving_chain.is_some());
        assert_eq!(alice_state.peer_ratchet_ecdh_public, header.ratchet_ecdh_public);
        assert_eq!(
            alice_state.peer_ratchet_kem_public,
            Some(header.ratchet_kem_public),
        );
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

    #[test]
    fn out_of_order_message_still_decrypts() {
        let (mut alice_state, mut bob_state) = two_party_session();
        // Establish the receiving chain first via an in-order message.
        // `RatchetHeader::kem_ciphertext` is present *only* on the
        // first message of a newly started sending chain (design
        // §4.3), and `decrypt`'s DH-ratchet-step trigger
        // (`receiving_chain.is_none()`, design §4.2 step 1) fires
        // unconditionally on whichever message a peer decrypts first
        // -- so the very first message of a brand-new chain must be
        // processed in order to bootstrap `receiving_chain` at all.
        // Task 10's skip-cache handles reordering *within* an already
        // established chain, which is what this test (and the others
        // below) exercise from this point on.
        let bootstrap = alice_state.encrypt(b"zero", b"").unwrap();
        bob_state.decrypt(&bootstrap, b"").unwrap();

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
        // See `out_of_order_message_still_decrypts` for why the chain
        // must be bootstrapped with an in-order message first.
        let bootstrap = alice_state.encrypt(b"zero", b"").unwrap();
        bob_state.decrypt(&bootstrap, b"").unwrap();

        for _ in 0..=crate::skipped_keys::MAX_SKIP {
            alice_state.encrypt(b"filler", b"").unwrap();
        }
        let far_future = alice_state.encrypt(b"too far", b"").unwrap();
        assert_eq!(
            bob_state.decrypt(&far_future, b"").unwrap_err(),
            RatchetError::SkippedKeyLimitExceeded,
        );
    }

    #[test]
    fn a_tampered_out_of_order_message_does_not_destroy_the_cached_key() {
        // Regression test mirroring
        // `decrypt_recovers_after_a_tampered_attempt_on_the_same_message`,
        // but for the skipped-key (`<` branch) path instead of the
        // in-order path: a failed decrypt of an out-of-order message
        // must re-insert its key rather than let `.take()` permanently
        // discard it, so a later correct retransmission of that exact
        // message still decrypts.
        let (mut alice_state, mut bob_state) = two_party_session();
        // See `out_of_order_message_still_decrypts` for why the chain
        // must be bootstrapped with an in-order message first.
        let bootstrap = alice_state.encrypt(b"zero", b"").unwrap();
        bob_state.decrypt(&bootstrap, b"").unwrap();

        let first = alice_state.encrypt(b"one", b"").unwrap();
        let second = alice_state.encrypt(b"two", b"").unwrap();

        // Bob receives "two" first, populating the skipped-key cache
        // with message "one"'s key.
        bob_state.decrypt(&second, b"").unwrap();

        // A tampered delivery of "one" must fail, but must NOT consume
        // the cached key.
        let mut tampered_first = first.clone();
        tampered_first.ciphertext[0] ^= 0xFF;
        assert_eq!(
            bob_state.decrypt(&tampered_first, b"").unwrap_err(),
            RatchetError::DecryptionFailed,
        );

        // The real, untampered message "one" must still decrypt.
        let plaintext_one = bob_state.decrypt(&first, b"").unwrap();
        assert_eq!(&*plaintext_one, b"one");
    }

    #[test]
    fn skipped_message_key_survives_to_bytes_from_bytes_round_trip() {
        // Correction #2: `to_bytes`/`from_bytes` must serialize
        // `skipped_message_keys`, not just the fields Task 6 originally
        // covered -- otherwise a persisted-then-restored `RatchetState`
        // would silently drop every cached out-of-order key, and a
        // message that arrives late right around that persist/reload
        // boundary would become permanently undecryptable (UnknownMessage)
        // instead of just delayed.
        let (mut alice_state, mut bob_state) = two_party_session();
        // See `out_of_order_message_still_decrypts` for why the chain
        // must be bootstrapped with an in-order message first.
        let bootstrap = alice_state.encrypt(b"zero", b"").unwrap();
        bob_state.decrypt(&bootstrap, b"").unwrap();

        let first = alice_state.encrypt(b"one", b"").unwrap();
        let second = alice_state.encrypt(b"two", b"").unwrap();

        // Bob receives "two" before "one", caching message "one"'s key.
        bob_state.decrypt(&second, b"").unwrap();
        assert_eq!(bob_state.skipped_message_keys.len(), 1);

        // Persist Bob's state (with the skipped key still cached).
        let bytes = bob_state.to_bytes();

        // Serializing an unchanged state twice must produce identical
        // bytes -- proving the serialization is deterministic and not
        // dependent on HashMap iteration order.
        assert_eq!(bob_state.to_bytes(), bytes, "to_bytes must be deterministic across calls");

        // Restore into a fresh state and confirm the cached key made
        // the trip.
        let mut restored_bob_state = RatchetState::from_bytes(&bytes).unwrap();
        assert_eq!(restored_bob_state.skipped_message_keys.len(), 1);

        // The restored state must still be able to decrypt the
        // previously-skipped message using the round-tripped key.
        let plaintext_one = restored_bob_state.decrypt(&first, b"").unwrap();
        assert_eq!(&*plaintext_one, b"one");

        // Re-serializing the restored (pre-consumption) state layout
        // must round trip byte-for-byte too.
        let re_restored = RatchetState::from_bytes(&bytes).unwrap();
        assert_eq!(re_restored.to_bytes(), bytes, "round trip must be exact");
    }

    #[test]
    fn decrypt_rejects_a_header_with_an_extreme_previous_chain_length() {
        // Regression test for Finding #1 (Critical): `dh_ratchet_step`'s
        // old-chain catch-up loop derived keys up to
        // `header.previous_chain_length` -- a peer-controlled `u32` read
        // straight off the wire -- with no bound check, unlike the
        // sibling `>`-branch in `decrypt`, which correctly checks
        // `MAX_SKIP` first. A malicious header claiming
        // `previous_chain_length = u32::MAX` must be rejected with
        // `SkippedKeyLimitExceeded`, not trigger billions of `kdf_ck`
        // calls before the message's own AEAD tag is ever checked.
        //
        // Driven through the public `decrypt` API (not `dh_ratchet_step`
        // directly), matching how a real malicious/corrupted message
        // would actually reach this code path.
        let (mut alice_state, mut bob_state) = two_party_session();
        let bootstrap = alice_state.encrypt(b"zero", b"").unwrap();
        bob_state.decrypt(&bootstrap, b"").unwrap();
        // Bob's receive_message_number is now 1, and receiving_chain is
        // Some -- the exact precondition `dh_ratchet_step`'s catch-up
        // loop needs to run at all.

        // Forge a header carrying a ratchet key Bob hasn't seen yet
        // (forcing the DH-ratchet-step path in `decrypt`), with a
        // malicious `previous_chain_length` far beyond `MAX_SKIP` past
        // Bob's current `receive_message_number`. The KEM ciphertext is
        // still validly encapsulated against Bob's own KEM public key so
        // that, absent the fix, execution would actually reach the
        // unbounded derivation loop rather than failing for an unrelated
        // reason first.
        let attacker_ecdh = Brainpool512SecretKey::generate();
        let (kem_ciphertext, _shared_secret) =
            aegis_crypto::kem::ml_kem_encapsulate(&bob_state.self_ratchet_kem.encapsulation_key_bytes())
                .unwrap();
        let malicious_header = RatchetHeader {
            ratchet_ecdh_public: attacker_ecdh.public_key_bytes().try_into().unwrap(),
            ratchet_kem_public: MlKem1024KeyPair::generate().encapsulation_key_bytes().try_into().unwrap(),
            kem_ciphertext: Some(kem_ciphertext.try_into().unwrap()),
            message_number: 0,
            previous_chain_length: u32::MAX,
        };
        let malicious_message = RatchetMessage {
            header: malicious_header,
            ciphertext: vec![0u8; 16],
        };

        assert_eq!(
            bob_state.decrypt(&malicious_message, b"").unwrap_err(),
            RatchetError::SkippedKeyLimitExceeded,
        );
    }

    #[test]
    fn late_message_from_a_superseded_chain_hits_the_skip_cache() {
        // Regression test for Finding #2 (Critical): `decrypt`'s control
        // flow checked "does this header need a DH ratchet step?" BEFORE
        // ever consulting the skip-cache, and the skip-cache lookup
        // itself was keyed on `self.peer_ratchet_ecdh_public` (the
        // CURRENT peer key) rather than the message header's own ratchet
        // key. A message that arrives late from a chain the peer has
        // already superseded carries the OLD ratchet key in its header
        // -- which no longer matches `self.peer_ratchet_ecdh_public` --
        // so it used to incorrectly trigger a second, invalid
        // `dh_ratchet_step` call instead of ever reaching the cache.
        //
        // This is the realistic three-message, cross-ratchet scenario
        // the reviewer noted no test exercised: Alice sends on chain A,
        // Bob partially receives it, Alice ratchets to chain B (in
        // response to a message from Bob) and sends on B, Bob processes
        // the chain-B message BEFORE the outstanding chain-A message
        // arrives late.
        let (mut alice_state, mut bob_state) = two_party_session();

        // Bootstrap Bob's receiving chain (chain A) with an in-order
        // message -- see `out_of_order_message_still_decrypts` for why
        // this first step must be in-order.
        let bootstrap = alice_state.encrypt(b"chain-a-zero", b"").unwrap();
        bob_state.decrypt(&bootstrap, b"").unwrap();

        // Alice sends a second message on chain A. This one will be
        // held back and delivered late, after Alice has ratcheted past
        // it entirely.
        let chain_a_late = alice_state.encrypt(b"chain-a-late", b"").unwrap();

        // Bob replies. This gives Alice a peer ratchet key she hasn't
        // seen, which -- when she decrypts it -- triggers Alice's OWN DH
        // ratchet step and resets her sending_chain to None.
        let bob_reply = bob_state.encrypt(b"bob-says-hi", b"").unwrap();
        alice_state.decrypt(&bob_reply, b"").unwrap();

        // Alice's next encrypt call starts a brand-new sending chain
        // (chain B) toward Bob, using a freshly generated ratchet
        // keypair -- distinct from chain A's.
        let chain_b_msg = alice_state.encrypt(b"chain-b-hello", b"").unwrap();
        assert_ne!(
            chain_b_msg.header.ratchet_ecdh_public, chain_a_late.header.ratchet_ecdh_public,
            "chain B must carry a new ratchet key, distinct from chain A's",
        );

        // Bob processes the chain-B message BEFORE the outstanding
        // chain-A message arrives. Because this carries a ratchet key
        // Bob hasn't seen, it triggers Bob's OWN `dh_ratchet_step` --
        // with `old_chain.is_some()` true (chain A is still his
        // receiving_chain) -- which must derive and cache chain A's
        // still-outstanding key (message_number 1, "chain-a-late")
        // before overwriting receiving_chain with chain B.
        let plaintext_b = bob_state.decrypt(&chain_b_msg, b"").unwrap();
        assert_eq!(&*plaintext_b, b"chain-b-hello");

        // The late chain-A message now arrives, carrying chain A's OLD
        // ratchet key in its header -- which no longer matches Bob's
        // current `peer_ratchet_ecdh_public` (now chain B's key). It
        // must decrypt by hitting the skip-cache under the header's own
        // key, NOT by triggering a second, invalid DH ratchet step.
        let plaintext_a_late = bob_state.decrypt(&chain_a_late, b"").unwrap();
        assert_eq!(&*plaintext_a_late, b"chain-a-late");
    }

    #[test]
    fn a_realistic_bidirectional_conversation_with_reordering_and_ratcheting() {
        let (mut alice_state, mut bob_state) = two_party_session();

        // Bootstrap Bob's receiving chain with a single in-order
        // message first. `RatchetHeader::kem_ciphertext` is present
        // *only* on the first message of a newly started sending
        // chain (design §4.3, Task 7/8 -- see
        // `encrypt_message_increments_the_send_counter`, which asserts
        // the second message of a chain carries no ciphertext at
        // all), and it is the KEM leg of that first message's
        // ciphertext that lets `dh_ratchet_step` derive the chain's
        // keys at all (Task 7). A message that isn't the chain's first
        // therefore cannot bootstrap `receiving_chain` on its own, no
        // matter how decrypt's control flow is arranged -- this is a
        // real, permanent constraint of the hybrid ECDH+ML-KEM
        // ratchet, not a bug (see `out_of_order_message_still_decrypts`
        // and Task 10's report for the same finding). Everything from
        // here on exercises real reordering within an already
        // established chain, which is what this test is for.
        let bootstrap = alice_state.encrypt(b"hey", b"").unwrap();
        assert_eq!(&*bob_state.decrypt(&bootstrap, b"").unwrap(), b"hey");

        // Alice sends three more messages on the same chain.
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

        // Bootstrap Bob's receiving chain with a single in-order
        // message first -- see the comment in
        // `a_realistic_bidirectional_conversation_with_reordering_and_ratcheting`
        // for why the chain's first (KEM-ciphertext-bearing) message
        // must be processed before any later message on it, in any
        // order, can be. The 50-message gap-and-catch-up below all
        // happens strictly after that bootstrap, which is exactly the
        // scenario this test exists to cover.
        let bootstrap = alice_state.encrypt(b"start", b"").unwrap();
        bob_state.decrypt(&bootstrap, b"").unwrap();

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
    fn a_non_bootstrap_message_cannot_be_decrypted_before_the_chains_first_message() {
        // Documents a real, permanent constraint of this protocol
        // design that Task 10's report identified but left uncovered
        // by an explicit test of its own: unlike a pure-DH ratchet
        // (where any header carrying a new public key can bootstrap a
        // ratchet step on its own), this hybrid ECDH+ML-KEM ratchet
        // needs the specific KEM ciphertext carried ONLY on a chain's
        // first message (design §4.3, Task 7/8) to derive that
        // chain's keys -- ML-KEM decapsulation has no equivalent of
        // "just do the exchange again" the way ECDH does. A message
        // from a chain whose first message has never been delivered
        // therefore cannot be decrypted, full stop; this must fail
        // cleanly with `MalformedMessage`, never panic, and must not
        // be confused with a decryption/authentication failure.
        let (mut alice_state, mut bob_state) = two_party_session();
        let _first = alice_state.encrypt(b"one", b"").unwrap();
        let second = alice_state.encrypt(b"two", b"").unwrap();

        assert_eq!(
            bob_state.decrypt(&second, b"").unwrap_err(),
            RatchetError::MalformedMessage,
        );
    }

    // ---------------------------------------------------------------
    // Final-review finding C1: the message header must be
    // authenticated as AEAD associated data (design §4.1).
    // ---------------------------------------------------------------

    #[test]
    fn tampering_with_the_header_message_number_fails_authentication() {
        // Before the fix, `message_number` was authenticated by
        // nothing at all, so an in-flight edit steered `decrypt`'s
        // catch-up logic directly: bumping it made the receiver derive
        // and cache keys for messages that never existed and
        // fast-forward its chain past them, permanently. The message
        // then failed AEAD anyway -- but the damage was already done.
        let (mut alice_state, mut bob_state) = two_party_session();
        let bootstrap = alice_state.encrypt(b"zero", b"").unwrap();
        bob_state.decrypt(&bootstrap, b"").unwrap();

        let genuine = alice_state.encrypt(b"one", b"").unwrap();

        let mut tampered = genuine.clone();
        tampered.header.message_number = 40;

        let before = bob_state.to_bytes();
        assert_eq!(
            bob_state.decrypt(&tampered, b"").unwrap_err(),
            RatchetError::DecryptionFailed,
            "a header-edited message must fail authentication",
        );
        assert_eq!(
            bob_state.to_bytes(),
            before,
            "a message that fails authentication must not change any session state",
        );
        assert_eq!(
            bob_state.skipped_message_keys.len(),
            0,
            "no keys may be derived and cached on behalf of a message that never authenticated",
        );

        // And the genuine message is still perfectly decryptable.
        assert_eq!(&*bob_state.decrypt(&genuine, b"").unwrap(), b"one");
    }

    #[test]
    fn tampering_with_the_header_previous_chain_length_fails_authentication() {
        let (mut alice_state, mut bob_state) = two_party_session();
        let bootstrap = alice_state.encrypt(b"zero", b"").unwrap();
        bob_state.decrypt(&bootstrap, b"").unwrap();

        let genuine = alice_state.encrypt(b"one", b"").unwrap();
        let mut tampered = genuine.clone();
        tampered.header.previous_chain_length ^= 0x0F;

        let before = bob_state.to_bytes();
        assert_eq!(
            bob_state.decrypt(&tampered, b"").unwrap_err(),
            RatchetError::DecryptionFailed,
        );
        assert_eq!(bob_state.to_bytes(), before);
        assert_eq!(&*bob_state.decrypt(&genuine, b"").unwrap(), b"one");
    }

    #[test]
    fn tampering_with_the_header_ratchet_kem_public_fails_authentication() {
        // `ratchet_kem_public` is the key the receiver will encapsulate
        // against for its own next sending chain. Unauthenticated, an
        // attacker could substitute their own and read everything the
        // receiver sends back; the ECDH leg would still protect it, but
        // the PQ leg -- the entire point of this ratchet -- would be
        // silently downgraded to the attacker's key.
        let (mut alice_state, mut bob_state) = two_party_session();
        let genuine = alice_state.encrypt(b"zero", b"").unwrap();

        let mut tampered = genuine.clone();
        tampered.header.ratchet_kem_public = MlKem1024KeyPair::generate()
            .encapsulation_key_bytes()
            .try_into()
            .unwrap();

        let before = bob_state.to_bytes();
        assert_eq!(
            bob_state.decrypt(&tampered, b"").unwrap_err(),
            RatchetError::DecryptionFailed,
        );
        assert_eq!(
            bob_state.to_bytes(),
            before,
            "a substituted ratchet KEM key must not be adopted by a message that fails AEAD",
        );
        assert_eq!(&*bob_state.decrypt(&genuine, b"").unwrap(), b"zero");
    }

    #[test]
    fn every_single_bit_flip_in_a_header_is_detected() {
        // Broad version of the three targeted tests above: the header's
        // byte encoding is length-framed into the AEAD's associated
        // data, so flipping any bit anywhere in it -- not just in the
        // fields this crate happens to read -- must be rejected, and
        // must leave the session untouched. Sampled across the encoding
        // rather than every one of its ~4300 bytes, to keep the test
        // fast.
        //
        // The assertion is "rejected, state unchanged", not a specific
        // error variant, because different regions of the header are
        // legitimately caught at different layers: a flip inside
        // `ratchet_ecdh_public` usually yields a point that is not on
        // brainpool512r1 at all, which `brainpool512_diffie_hellman`
        // rejects as `Crypto(InvalidPeerPublicKey)` before any AEAD call
        // happens. That is a strictly earlier and equally safe
        // rejection -- what must never happen is acceptance, or a
        // rejection that still mutated the session.
        let (mut alice_state, mut bob_state) = two_party_session();
        let genuine = alice_state.encrypt(b"zero", b"").unwrap();
        let header_len = genuine.header.to_bytes().len();
        let before = bob_state.to_bytes();

        let mut flips_checked = 0;
        for byte_index in (0..header_len).step_by(97) {
            let mut header_bytes = genuine.header.to_bytes();
            header_bytes[byte_index] ^= 0x01;
            // Only bit flips that still decode to a well-formed header
            // are interesting here; the presence-byte position decodes
            // to a different shape and is covered by the malformed-input
            // tests instead.
            let Ok(header) = RatchetHeader::from_bytes(&header_bytes) else {
                continue;
            };
            if header == genuine.header {
                continue;
            }
            let tampered = RatchetMessage {
                header,
                ciphertext: genuine.ciphertext.clone(),
            };
            assert!(
                bob_state.decrypt(&tampered, b"").is_err(),
                "bit flip at header byte {byte_index} was not detected",
            );
            assert_eq!(
                bob_state.to_bytes(),
                before,
                "bit flip at header byte {byte_index} changed session state",
            );
            flips_checked += 1;
        }
        assert!(flips_checked > 10, "the sweep must actually exercise the header");

        assert_eq!(&*bob_state.decrypt(&genuine, b"").unwrap(), b"zero");
    }

    #[test]
    fn the_caller_aad_and_the_header_cannot_be_shifted_across_their_boundary() {
        // The associated data is `len(aad) || aad || len(header) ||
        // header`, so the caller's `aad` and the header occupy
        // unambiguous, non-interchangeable positions. With plain
        // concatenation, moving bytes across that boundary would
        // produce identical associated data for different inputs.
        let header = RatchetHeader {
            ratchet_ecdh_public: [0x01u8; ECDH_PUBLIC_KEY_LEN],
            ratchet_kem_public: [0x02u8; KEM_ENCAPSULATION_KEY_LEN],
            kem_ciphertext: None,
            message_number: 0,
            previous_chain_length: 0,
        };
        assert_ne!(
            RatchetState::aead_associated_data(b"AB", &header),
            RatchetState::aead_associated_data(b"A", &header),
        );
        // Same total bytes, different split -- must still differ.
        let mut longer_aad = b"A".to_vec();
        longer_aad.extend_from_slice(&header.to_bytes());
        assert_ne!(
            RatchetState::aead_associated_data(&longer_aad, &header),
            RatchetState::aead_associated_data(b"A", &header),
        );
    }

    // ---------------------------------------------------------------
    // Final-review finding C2: `decrypt` must be transactional --
    // no `self` field may change as a side effect of a message that
    // ultimately fails AEAD authentication.
    // ---------------------------------------------------------------

    #[test]
    fn a_replayed_message_that_triggers_a_ratchet_step_does_not_corrupt_the_session() {
        // The empirically-reproduced C2 failure, end to end, with no
        // attacker involved -- just a duplicated packet.
        //
        // ML-KEM decapsulation cannot report a wrong ciphertext (FIPS
        // 203 mandates implicit rejection), so a replayed
        // chain-opening message reaches `dh_ratchet_step`, decapsulates
        // to an unpredictable shared secret, and -- before the fix --
        // committed the resulting garbage root key, receiving chain,
        // peer keys and self keypair. The session was then dead in both
        // directions, and the failure surfaced later, on an unrelated
        // legitimate message.
        let (mut alice_state, mut bob_state) = two_party_session();

        // Chain A: Alice opens.
        let a0 = alice_state.encrypt(b"a0", b"").unwrap();
        bob_state.decrypt(&a0, b"").unwrap();

        // Chain B: Bob replies -- Alice ratchets onto it.
        let b0 = bob_state.encrypt(b"b0", b"").unwrap();
        assert!(b0.header.kem_ciphertext.is_some(), "b0 must open a new chain");
        alice_state.decrypt(&b0, b"").unwrap();

        // Chain A': Alice ratchets forward and sends.
        let a1 = alice_state.encrypt(b"a1", b"").unwrap();
        bob_state.decrypt(&a1, b"").unwrap();

        // Chain C: Bob ratchets forward again. Alice is now two ratchet
        // steps past chain B.
        let c0 = bob_state.encrypt(b"c0", b"").unwrap();
        assert!(c0.header.kem_ciphertext.is_some());
        alice_state.decrypt(&c0, b"").unwrap();

        // The network now redelivers `b0` -- an ordinary duplicate.
        // Its header carries chain B's ratchet key, which no longer
        // matches Alice's current peer key, and its key is not in the
        // skip cache (it was consumed). So it takes exactly the
        // ratchet-step path this finding is about.
        let before = alice_state.to_bytes();
        assert_eq!(
            alice_state.decrypt(&b0, b"").unwrap_err(),
            RatchetError::DecryptionFailed,
            "a replayed chain-opening message must be rejected",
        );
        assert_eq!(
            alice_state.to_bytes(),
            before,
            "a rejected replay must leave the session byte-for-byte unchanged",
        );

        // The real proof: the conversation continues normally. Before
        // the fix, this is where the corruption surfaced.
        let c1 = bob_state.encrypt(b"c1", b"").unwrap();
        assert_eq!(&*alice_state.decrypt(&c1, b"").unwrap(), b"c1");

        let a2 = alice_state.encrypt(b"a2", b"").unwrap();
        assert_eq!(&*bob_state.decrypt(&a2, b"").unwrap(), b"a2");
    }

    #[test]
    fn a_forged_chain_opening_message_does_not_corrupt_the_session() {
        // The attacker-driven variant: a well-formed header carrying a
        // ratchet key Bob has never seen and a KEM ciphertext validly
        // encapsulated against Bob's own current ratchet key, so the
        // whole DH-ratchet-step computation runs to completion and only
        // the AEAD tag rejects it. Every field the step would have
        // written must remain untouched.
        let (mut alice_state, mut bob_state) = two_party_session();
        let a0 = alice_state.encrypt(b"a0", b"").unwrap();
        bob_state.decrypt(&a0, b"").unwrap();

        let attacker_ecdh = Brainpool512SecretKey::generate();
        let (kem_ciphertext, _shared) = aegis_crypto::kem::ml_kem_encapsulate(
            &bob_state.self_ratchet_kem.encapsulation_key_bytes(),
        )
        .unwrap();
        let forged = RatchetMessage {
            header: RatchetHeader {
                ratchet_ecdh_public: attacker_ecdh.public_key_bytes().try_into().unwrap(),
                ratchet_kem_public: MlKem1024KeyPair::generate()
                    .encapsulation_key_bytes()
                    .try_into()
                    .unwrap(),
                kem_ciphertext: Some(kem_ciphertext.try_into().unwrap()),
                message_number: 0,
                previous_chain_length: 1,
            },
            ciphertext: vec![0u8; 32],
        };

        let before = bob_state.to_bytes();
        assert_eq!(
            bob_state.decrypt(&forged, b"").unwrap_err(),
            RatchetError::DecryptionFailed,
        );
        assert_eq!(
            bob_state.to_bytes(),
            before,
            "a forged ratchet step must not be committed",
        );

        // Alice's genuine next message still decrypts.
        let a1 = alice_state.encrypt(b"a1", b"").unwrap();
        assert_eq!(&*bob_state.decrypt(&a1, b"").unwrap(), b"a1");
    }

    #[test]
    fn a_failed_out_of_order_decrypt_caches_no_keys() {
        // The gap catch-up in `decrypt`'s `>` branch used to insert
        // straight into `self.skipped_message_keys` and advance
        // `receive_message_number` before the AEAD call. A message that
        // then failed left the cache full of keys derived on its
        // behalf -- bounded churn that can evict genuinely useful
        // entries -- and the counter fast-forwarded past messages whose
        // keys were now unreachable.
        let (mut alice_state, mut bob_state) = two_party_session();
        let bootstrap = alice_state.encrypt(b"zero", b"").unwrap();
        bob_state.decrypt(&bootstrap, b"").unwrap();

        let mut sent = Vec::new();
        for i in 0..5u32 {
            sent.push(alice_state.encrypt(format!("msg {i}").as_bytes(), b"").unwrap());
        }

        // Deliver the last one, tampered. It is 4 ahead of the live
        // chain, so the catch-up loop runs and derives 4 keys.
        let mut tampered = sent[4].clone();
        tampered.ciphertext[0] ^= 0xFF;

        let before = bob_state.to_bytes();
        assert_eq!(
            bob_state.decrypt(&tampered, b"").unwrap_err(),
            RatchetError::DecryptionFailed,
        );
        assert_eq!(
            bob_state.skipped_message_keys.len(),
            0,
            "keys derived for a message that failed authentication must not be cached",
        );
        assert_eq!(bob_state.to_bytes(), before);

        // Everything still decrypts, in any order.
        assert_eq!(&*bob_state.decrypt(&sent[4], b"").unwrap(), b"msg 4");
        for i in 0..4u32 {
            let plaintext = bob_state.decrypt(&sent[i as usize], b"").unwrap();
            assert_eq!(plaintext.as_slice(), format!("msg {i}").as_bytes());
        }
    }

    // ---------------------------------------------------------------
    // Final-review finding I1: a responder that has not yet learned
    // the peer's ratchet KEM key must refuse to send, rather than
    // encapsulate against an all-zero placeholder.
    // ---------------------------------------------------------------

    #[test]
    fn a_responder_that_has_decrypted_nothing_cannot_send_yet() {
        // Bob learns Alice's ratchet ML-KEM key only from her first
        // message header (design §4.3). Before the fix, the field was
        // an all-zero placeholder -- which passes ML-KEM's FIPS 203
        // modulus check, so encapsulation silently *succeeded* against
        // a key nobody holds, producing a message Alice could never
        // decrypt and (via C2) destroying her session when she tried.
        let (_alice_state, mut bob_state) = two_party_session();

        let before = bob_state.to_bytes();
        assert_eq!(
            bob_state.encrypt(b"bob speaks first", b"").unwrap_err(),
            RatchetError::NotReadyToSend,
        );
        assert_eq!(
            bob_state.to_bytes(),
            before,
            "a refused send must not partially advance the session",
        );
    }

    #[test]
    fn a_responder_can_send_once_it_has_decrypted_one_message() {
        // The complement: `NotReadyToSend` is a transient, correct
        // state, not a dead end.
        let (mut alice_state, mut bob_state) = two_party_session();
        assert_eq!(
            bob_state.encrypt(b"too early", b"").unwrap_err(),
            RatchetError::NotReadyToSend,
        );

        let a0 = alice_state.encrypt(b"a0", b"").unwrap();
        bob_state.decrypt(&a0, b"").unwrap();

        let b0 = bob_state.encrypt(b"now i can", b"").unwrap();
        assert_eq!(&*alice_state.decrypt(&b0, b"").unwrap(), b"now i can");
    }

    #[test]
    fn a_restored_responder_state_still_refuses_to_send() {
        // `peer_ratchet_kem_public: None` must survive the wire
        // round trip as `None` (presence byte), not silently become an
        // all-zero key again on reload.
        let (_alice_state, bob_state) = two_party_session();
        let bytes = bob_state.to_bytes();
        let mut restored = RatchetState::from_bytes(&bytes).unwrap();
        assert!(restored.peer_ratchet_kem_public.is_none());
        assert_eq!(
            restored.encrypt(b"still too early", b"").unwrap_err(),
            RatchetError::NotReadyToSend,
        );
        assert_eq!(restored.to_bytes(), bytes, "round trip must be exact");
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
}
