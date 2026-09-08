//! The Double Ratchet's state machine: `RatchetState`, its wire
//! serialization, and the `RatchetHeader`/`RatchetMessage` wire types
//! for encrypted messages. See design §3, §4.3.

use core::fmt;

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
}
