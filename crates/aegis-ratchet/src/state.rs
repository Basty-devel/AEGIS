//! The Double Ratchet's state machine: `RatchetState`, its wire
//! serialization, and the `RatchetHeader`/`RatchetMessage` wire types
//! for encrypted messages. See design §3, §4.3.

use core::fmt;

use crate::error::RatchetError;
use crate::kdf_chain::{kdf_ck, kdf_rk, CHAIN_KEY_LEN, ROOT_KEY_LEN};
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
            .field("peer_ratchet_kem_public", &"<public, omitted>")
            .field("send_message_number", &self.send_message_number)
            .field("receive_message_number", &self.receive_message_number)
            .field("previous_chain_length", &self.previous_chain_length)
            .field("skipped_message_keys_len", &self.skipped_message_keys.len())
            .finish()
    }
}

impl RatchetState {
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
            peer_ratchet_kem_public: peer_signed_pre_key_kem_public,
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
            // only her first message's header carries it. Zeroed here;
            // Task 7's DH ratchet step overwrites it (and populates
            // receiving_chain) the moment decrypt_message sees that
            // header, before this placeholder value is ever used for
            // anything.
            peer_ratchet_kem_public: [0u8; KEM_ENCAPSULATION_KEY_LEN],
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
    /// -- `peer_ratchet_kem_public` -- the three `u32` counters,
    /// big-endian. [`Self::from_bytes`] must consume fields in this
    /// exact order.
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
        out.extend_from_slice(&self.peer_ratchet_kem_public);
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
        let peer_ratchet_kem_public = cursor
            .take_array::<KEM_ENCAPSULATION_KEY_LEN>()
            .map_err(|_| RatchetError::MalformedMessage)?;

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

    /// A DH ratchet step, triggered when `header` carries a peer
    /// ratchet public key not yet seen (design §3.2). Advances
    /// `receiving_chain` using `header`'s KEM ciphertext (which must
    /// be present -- the first message of any new peer chain always
    /// carries one, by construction of [`Self::start_sending_chain`]),
    /// generates a fresh self-ratchet keypair, and starts a new
    /// `sending_chain` toward the peer's newly announced public keys.
    pub(crate) fn dh_ratchet_step(&mut self, header: &RatchetHeader) -> Result<(), RatchetError> {
        // Before overwriting the current receiving chain, derive and
        // cache the message keys for any messages on it that were
        // never received (design §5) -- otherwise a message that was
        // in flight when the peer ratcheted forward would be silently
        // stranded: once `receiving_chain` is replaced below, there is
        // no way to derive that old chain's keys again.
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
            &message_key,
            &nonce,
            aad,
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

        if message.header.message_number < self.receive_message_number {
            // Already-advanced-past message number: look it up in the
            // skipped-key cache rather than the live chain (the live
            // chain has already moved past this point).
            let message_number = message.header.message_number;
            let sender = self.peer_ratchet_ecdh_public;
            let key = self
                .skipped_message_keys
                .take(sender, message_number)
                .ok_or(RatchetError::UnknownMessage)?;
            let nonce = [0u8; 12];
            return match aegis_crypto::aead::decrypt(
                aegis_crypto::aead::AeadAlgorithm::Aes256Gcm,
                &key,
                &nonce,
                aad,
                &message.ciphertext,
            ) {
                Ok(plaintext) => Ok(Zeroizing::new(plaintext)),
                Err(_) => {
                    // Re-insert rather than let `.take()` permanently
                    // discard this key: a tampered/corrupted delivery
                    // of this message must not also make a later,
                    // correct retransmission of the same message
                    // undecryptable. Mirrors the same "don't commit
                    // state until the fallible step succeeds"
                    // principle Task 9's review caught in the in-order
                    // path (chain.chain_key advancing before the AEAD
                    // call was known to succeed) -- applied here to
                    // the skipped-key cache instead of the chain key.
                    self.skipped_message_keys.insert(sender, message_number, key);
                    Err(RatchetError::DecryptionFailed)
                }
            };
        }

        if message.header.message_number > self.receive_message_number {
            // Message arrived ahead of the live chain: derive and cache
            // every intervening key so those messages can still
            // decrypt later, then fast-forward the chain in place to
            // the requested message number.
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

        // Derive the next chain key and this message's key, but do NOT
        // commit `chain.chain_key` yet: the AEAD call below is fallible
        // (tampered ciphertext, wrong AAD), and if it fails we must
        // leave the chain key and receive_message_number exactly as
        // they were, so a later correct retransmission of this same
        // message can still be decrypted. Committing the advance here
        // unconditionally would strand the chain key one position ahead
        // of the counter on failure, permanently breaking recovery.
        let (new_chain_key, message_key) = kdf_ck(&chain.chain_key);

        let nonce = [0u8; 12]; // matches encrypt_message's nonce construction -- see Task 8 notes
        let plaintext = aegis_crypto::aead::decrypt(
            aegis_crypto::aead::AeadAlgorithm::Aes256Gcm,
            &message_key,
            &nonce,
            aad,
            &message.ciphertext,
        )
        .map_err(|_| RatchetError::DecryptionFailed)?;

        // Only now, after decrypt succeeded, commit the chain advance.
        chain.chain_key = new_chain_key;
        self.receive_message_number += 1;

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
}
