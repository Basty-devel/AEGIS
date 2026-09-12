//! Signed, rate-limited capability tokens. See `AEGIS.Plan.V0.2.md`
//! Section 6.3: "Each account holds a signed, rate-limited capability
//! token from its identity key. Mailbox nodes validate the token to
//! enforce per-account rate limits — this is the *only* bookkeeping a
//! node performs." This module is the token half of that sentence; the
//! rate-limit bookkeeping half is [`crate::rate_limit`].
//!
//! A token is self-certifying, in the same spirit as spec Section 6.2's
//! "a user's identity is simply their public key": it carries its own
//! claimed Ed25519 + ML-DSA-87 public keys, and [`CapabilityToken::verify`]
//! proves only that whoever produced the token holds the matching
//! private keys — a mailbox node does not need to already know the
//! account to validate a token presented to it.
//!
//! # Wire format
//!
//! ```text
//! offset  size  field
//! 0       4     magic: b"CAP1"
//! 4       32    ed25519_pub
//! 36      2     ml_dsa87_pub_len, u16 big-endian
//! 38      N     ml_dsa87_pub (N = ml_dsa87_pub_len)
//! 38+N    8     issued_at, u64 big-endian, unix seconds
//! 46+N    8     expires_at, u64 big-endian, unix seconds
//! 54+N    16    nonce
//! 70+N    64    ed25519 signature
//! 134+N   2     ml_dsa87_sig_len, u16 big-endian
//! 136+N   M     ml_dsa87 signature (M = ml_dsa87_sig_len)
//! ```
//!
//! # Why `issued_at`/`now` are caller-supplied, never read from the
//! system clock
//!
//! Every timestamp this module touches is a plain `u64` parameter —
//! [`CapabilityToken::issue`] takes `issued_at`, [`CapabilityToken::verify`]
//! takes `now`. Neither calls `SystemTime::now()` internally. This
//! keeps the whole module a pure function of its inputs, which is what
//! makes [`tests::token_verifies_up_to_but_not_including_expiry`] and
//! every other boundary test in this file exact and reproducible rather
//! than racing the real clock. The caller (eventually `aegis-net`'s
//! mailbox-facing runtime) supplies the real wall-clock time.

use crate::error::NetError;
use aegis_crypto::signature::{verify_dual, DualKeyPair, DualSignature};

/// The maximum validity window [`CapabilityToken::issue`] will accept,
/// in seconds (24 hours). Not specified by `AEGIS.Plan.V0.2.md` itself
/// — this is this crate's own design decision, documented here rather
/// than left implicit, so a caller reading an `InvalidValidityWindow`
/// error can find out why. 24 hours bounds how long a compromised or
/// leaked token stays useful without forcing re-issuance so often that
/// legitimate clients would be re-authenticating constantly; revisit
/// this constant if `aegis-net`'s eventual mailbox-session design wants
/// a different tradeoff.
pub const MAX_TOKEN_VALIDITY_SECONDS: u64 = 86_400;

const MAGIC: [u8; 4] = *b"CAP1";

/// Domain-separation label mixed into every token's signed payload.
/// Distinct from every other domain label used elsewhere in this
/// workspace (`aegis_crypto::sas::SAS_CONTEXT`, `aegis-file`'s chunk
/// AAD label, and so on) — the same "never let two different signed/
/// authenticated purposes share a label" discipline this workspace
/// applies everywhere a value is bound into a MAC, AEAD AAD, or
/// signature.
const DOMAIN_LABEL: &[u8] = b"AEGIS-NET-v1-capability-token";

/// Wire protocol version byte, matching `aegis_crypto::version`'s
/// `ProtocolVersion::V1` — bound into every token's signed payload so a
/// future incompatible token format cannot be replayed against this
/// one's verification logic.
const PROTOCOL_VERSION: u8 = 1;

const NONCE_LEN: usize = 16;
const ED25519_SIG_LEN: usize = 64;

/// A signed, time-bounded capability token proving control of an
/// identity keypair, per spec Section 6.3.
///
/// Deliberately does not derive `Debug`/`Clone`/`PartialEq`: its
/// `signature` field is `aegis_crypto::signature::DualSignature`, which
/// (correctly, for a type that could otherwise invite treating a
/// signature as comparable/copyable state) derives none of those
/// itself, and Rust's orphan rules mean this crate cannot add foreign-
/// trait impls for that foreign type. Compare tokens by their public
/// accessors (`ed25519_identity`, `issued_at`, `expires_at`, ...) or by
/// `to_bytes()` equality instead.
pub struct CapabilityToken {
    ed25519_pub: [u8; 32],
    ml_dsa87_pub: Vec<u8>,
    issued_at: u64,
    expires_at: u64,
    nonce: [u8; NONCE_LEN],
    signature: DualSignature,
}

/// Manual (non-derived) `Debug` impl: `DualSignature` (from
/// `aegis_crypto`) implements no traits at all in its home crate, and
/// the orphan rule blocks adding `Debug` to it from here, so
/// `#[derive(Debug)]` on `CapabilityToken` itself is not an option.
/// Formats the signature field by its two components instead of
/// delegating to a `DualSignature: Debug` impl that cannot exist in
/// this crate — the raw signature bytes are not secret (a signature
/// is meant to be published alongside the message it covers), so
/// there is no zeroization/redaction concern in printing them.
impl std::fmt::Debug for CapabilityToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityToken")
            .field("ed25519_pub", &self.ed25519_pub)
            .field("ml_dsa87_pub_len", &self.ml_dsa87_pub.len())
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("nonce", &self.nonce)
            .field("signature_ed25519", &self.signature.ed25519)
            .field("signature_ml_dsa87_len", &self.signature.ml_dsa87.len())
            .finish()
    }
}

/// The exact bytes [`CapabilityToken::issue`] signs and
/// [`CapabilityToken::verify`] re-derives and checks against. A free
/// function (not a method) because `issue` needs it before a
/// `CapabilityToken` exists to call a method on.
///
/// Every variable-length field is length-framed (`u16` big-endian
/// prefix) even though only one such field exists here today — the
/// same anti-ambiguity discipline `aegis_crypto::kdf::derive_key`'s doc
/// comment explains in detail: an unframed variable-length field lets
/// two different logical inputs serialise to identical bytes, which
/// would let two different tokens collide onto the same signed
/// payload.
fn signing_payload(
    ed25519_pub: &[u8; 32],
    ml_dsa87_pub: &[u8],
    issued_at: u64,
    expires_at: u64,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        DOMAIN_LABEL.len() + 1 + 32 + 2 + ml_dsa87_pub.len() + 8 + 8 + NONCE_LEN,
    );
    payload.extend_from_slice(DOMAIN_LABEL);
    payload.push(PROTOCOL_VERSION);
    payload.extend_from_slice(ed25519_pub);
    // Callers of this function (`issue` and `verify`) are both
    // responsible for having already bounded `ml_dsa87_pub.len()` to
    // `u16::MAX` before reaching here — `issue` via its own explicit
    // check, `verify` because it only ever calls this with fields
    // decoded by `from_bytes`, which enforces the same bound while
    // parsing. `as u16` here is therefore lossless in every reachable
    // call, not a silent truncation risk.
    payload.extend_from_slice(&(ml_dsa87_pub.len() as u16).to_be_bytes());
    payload.extend_from_slice(ml_dsa87_pub);
    payload.extend_from_slice(&issued_at.to_be_bytes());
    payload.extend_from_slice(&expires_at.to_be_bytes());
    payload.extend_from_slice(nonce);
    payload
}

/// Read exactly `len` bytes at `*cursor`, advancing it, or fail closed
/// with [`NetError::Truncated`] — never an out-of-bounds slice panic on
/// attacker-controlled `bytes`/`len`.
fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], NetError> {
    let end = cursor.checked_add(len).ok_or(NetError::Truncated)?;
    if end > bytes.len() {
        return Err(NetError::Truncated);
    }
    let slice = &bytes[*cursor..end];
    *cursor = end;
    Ok(slice)
}

/// Read a `u16`-big-endian-length-prefixed field, rejecting an
/// implausible declared length (one exceeding what could possibly
/// remain in `bytes`) as [`NetError::MalformedLength`] before ever
/// attempting to slice that far — distinct from [`take`]'s
/// [`NetError::Truncated`] only in which check catches a given
/// malformed input first; both paths are equally panic-free.
fn take_framed<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<&'a [u8], NetError> {
    let len_bytes = take(bytes, cursor, 2)?;
    let len =
        u16::from_be_bytes(len_bytes.try_into().expect("take(2) guarantees 2 bytes")) as usize;
    if cursor.checked_add(len).is_none_or(|end| end > bytes.len()) {
        return Err(NetError::MalformedLength { field });
    }
    take(bytes, cursor, len)
}

impl CapabilityToken {
    /// Issue a new token proving control of `identity`, valid from
    /// `issued_at` for `validity_seconds` (unix seconds).
    ///
    /// # Errors
    ///
    /// [`NetError::InvalidValidityWindow`] if `validity_seconds` is `0`,
    /// exceeds [`MAX_TOKEN_VALIDITY_SECONDS`], or `issued_at +
    /// validity_seconds` overflows `u64`.
    pub fn issue(
        identity: &DualKeyPair,
        issued_at: u64,
        validity_seconds: u64,
    ) -> Result<Self, NetError> {
        if validity_seconds == 0 {
            return Err(NetError::InvalidValidityWindow {
                reason: "validity_seconds must be at least 1",
            });
        }
        if validity_seconds > MAX_TOKEN_VALIDITY_SECONDS {
            return Err(NetError::InvalidValidityWindow {
                reason: "validity_seconds exceeds MAX_TOKEN_VALIDITY_SECONDS",
            });
        }
        let expires_at =
            issued_at
                .checked_add(validity_seconds)
                .ok_or(NetError::InvalidValidityWindow {
                    reason: "issued_at + validity_seconds overflows u64",
                })?;

        let ed25519_pub = identity.ed25519_public_bytes();
        let ml_dsa87_pub = identity.ml_dsa87_public_bytes();
        if ml_dsa87_pub.len() > u16::MAX as usize {
            // Unreachable for any real ML-DSA-87 key (FIPS 204 fixes
            // its encoded public-key length at 2592 bytes), but this
            // crate does not hardcode that constant — bounding it
            // explicitly here means a future ml-dsa upgrade that
            // changed the size would fail this check loudly instead of
            // silently truncating the length prefix in
            // `signing_payload`/`to_bytes`.
            return Err(NetError::MalformedLength {
                field: "ml_dsa87_pub",
            });
        }

        let mut nonce = [0u8; NONCE_LEN];
        // Not attacker-controlled (no wire data reaches this call) —
        // fail-closed panic on OS RNG failure, matching every other
        // fresh-randomness site in this workspace
        // (`aegis_crypto::aead::ChunkNonceSequence::random`,
        // `DualKeyPair::generate`).
        getrandom::fill(&mut nonce).expect("OS RNG failure");

        let payload = signing_payload(&ed25519_pub, &ml_dsa87_pub, issued_at, expires_at, &nonce);
        let signature = identity.sign(&payload);

        Ok(Self {
            ed25519_pub,
            ml_dsa87_pub,
            issued_at,
            expires_at,
            nonce,
            signature,
        })
    }

    /// Verify this token is both genuinely signed by the identity it
    /// claims and still within its validity window at `now`.
    ///
    /// # Check ordering: authenticate before trusting any field
    ///
    /// Every field on a freshly [`CapabilityToken::from_bytes`]-decoded
    /// token is attacker-controlled until this method's signature check
    /// passes. Earlier revisions of this method checked `issued_at >
    /// expires_at` *before* verifying the signature — a "decide before
    /// you authenticate" ordering bug: it meant a hand-tampered token
    /// could steer which `NetError` variant came back (still rejected
    /// either way, but by branching control flow on unauthenticated
    /// wire bytes, which is the wrong general habit even when the
    /// specific case is harmless). The signature is now verified
    /// *first*, and only a token that has already proven authenticity
    /// has its `issued_at`/`expires_at` trusted for the structural and
    /// temporal checks that follow.
    ///
    /// # Errors
    ///
    /// - [`NetError::SignatureInvalid`] if the dual signature does not
    ///   verify against this token's own claimed fields.
    /// - [`NetError::InvalidValidityWindow`] if `issued_at > expires_at`
    ///   — impossible for anything [`CapabilityToken::issue`] produced
    ///   (and, since it is checked only after the signature above has
    ///   already verified, impossible for any *tampered* token too: the
    ///   signature covers both fields, so a genuine signature over an
    ///   inverted window could only come from an [`CapabilityToken::issue`]
    ///   caller that was itself modified to allow it — defense in depth
    ///   against exactly that).
    /// - [`NetError::TokenExpired`] if `now >= expires_at` (the
    ///   interval is half-open: `expires_at` itself is already
    ///   expired).
    pub fn verify(&self, now: u64) -> Result<(), NetError> {
        let payload = signing_payload(
            &self.ed25519_pub,
            &self.ml_dsa87_pub,
            self.issued_at,
            self.expires_at,
            &self.nonce,
        );
        if !verify_dual(
            &self.ed25519_pub,
            &self.ml_dsa87_pub,
            &payload,
            &self.signature,
        ) {
            return Err(NetError::SignatureInvalid);
        }
        if self.issued_at > self.expires_at {
            return Err(NetError::InvalidValidityWindow {
                reason: "issued_at is after expires_at",
            });
        }
        if now >= self.expires_at {
            return Err(NetError::TokenExpired {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(())
    }

    /// The Ed25519 identity public key this token claims. Not yet
    /// verified as genuine until [`CapabilityToken::verify`] succeeds —
    /// callers must not use this for authorization decisions before
    /// calling `verify`.
    pub fn ed25519_identity(&self) -> &[u8; 32] {
        &self.ed25519_pub
    }

    /// The ML-DSA-87 identity public key this token claims (see
    /// [`CapabilityToken::ed25519_identity`]'s caveat — same applies
    /// here).
    pub fn ml_dsa87_public_bytes(&self) -> &[u8] {
        &self.ml_dsa87_pub
    }

    /// This token's claimed issuance time, unix seconds.
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// This token's claimed expiry time, unix seconds.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Encode this token to its wire format (see the module doc
    /// comment for the exact layout).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.ed25519_pub);
        // Safe: `self.ml_dsa87_pub.len()` is bounded to `u16::MAX` by
        // every construction path (`issue`'s explicit check;
        // `from_bytes`'s length-prefix parsing can never produce a
        // longer `Vec` than a `u16` could have declared).
        out.extend_from_slice(&(self.ml_dsa87_pub.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ml_dsa87_pub);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.signature.ed25519);
        // ML-DSA-87's encoded signature length is fixed by FIPS 204
        // (well under `u16::MAX`) for every signature this crate itself
        // ever produces via `DualKeyPair::sign`; no additional bound
        // check is needed the way `ml_dsa87_pub` above needed one,
        // since this field is never populated from unbounded user
        // input on the encode path.
        out.extend_from_slice(&(self.signature.ml_dsa87.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature.ml_dsa87);
        out
    }

    /// Decode a token from its wire format. Performs no cryptographic
    /// or temporal verification — call [`CapabilityToken::verify`]
    /// afterward before trusting anything about the decoded token, the
    /// same parse/verify separation `aegis-file`'s `stream` module
    /// uses for its own wire header.
    ///
    /// # Errors
    ///
    /// [`NetError::BadMagic`], [`NetError::Truncated`],
    /// [`NetError::MalformedLength`], or [`NetError::TrailingData`] for
    /// a malformed encoding. Never panics on any input, including an
    /// empty slice or a declared length exceeding what remains.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NetError> {
        let mut cursor = 0usize;

        let magic = take(bytes, &mut cursor, 4)?;
        if magic != MAGIC {
            return Err(NetError::BadMagic);
        }

        let ed25519_pub: [u8; 32] = take(bytes, &mut cursor, 32)?
            .try_into()
            .expect("take(32) guarantees 32 bytes");

        let ml_dsa87_pub = take_framed(bytes, &mut cursor, "ml_dsa87_pub")?.to_vec();

        let issued_at = u64::from_be_bytes(
            take(bytes, &mut cursor, 8)?
                .try_into()
                .expect("take(8) guarantees 8 bytes"),
        );
        let expires_at = u64::from_be_bytes(
            take(bytes, &mut cursor, 8)?
                .try_into()
                .expect("take(8) guarantees 8 bytes"),
        );
        let nonce: [u8; NONCE_LEN] = take(bytes, &mut cursor, NONCE_LEN)?
            .try_into()
            .expect("take(NONCE_LEN) guarantees NONCE_LEN bytes");

        let ed25519_sig: [u8; ED25519_SIG_LEN] = take(bytes, &mut cursor, ED25519_SIG_LEN)?
            .try_into()
            .expect("take(ED25519_SIG_LEN) guarantees ED25519_SIG_LEN bytes");

        let ml_dsa87_sig = take_framed(bytes, &mut cursor, "ml_dsa87_sig")?.to_vec();

        if cursor != bytes.len() {
            return Err(NetError::TrailingData);
        }

        Ok(Self {
            ed25519_pub,
            ml_dsa87_pub,
            issued_at,
            expires_at,
            nonce,
            signature: DualSignature {
                ed25519: ed25519_sig,
                ml_dsa87: ml_dsa87_sig,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{signing_payload, CapabilityToken, MAX_TOKEN_VALIDITY_SECONDS, NONCE_LEN};
    use crate::error::NetError;
    use aegis_crypto::signature::DualKeyPair;

    #[test]
    fn issued_token_verifies_immediately() {
        let identity = DualKeyPair::generate();
        let token = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        assert!(token.verify(1_000).is_ok());
    }

    #[test]
    fn token_verifies_up_to_but_not_including_expiry() {
        let identity = DualKeyPair::generate();
        let token = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        assert!(token.verify(4_599).is_ok());
        let err = token.verify(4_600).unwrap_err();
        assert!(matches!(
            err,
            NetError::TokenExpired {
                expires_at: 4_600,
                now: 4_600
            }
        ));
    }

    #[test]
    fn issuing_with_zero_validity_is_rejected() {
        let identity = DualKeyPair::generate();
        let err = CapabilityToken::issue(&identity, 1_000, 0).unwrap_err();
        assert!(matches!(err, NetError::InvalidValidityWindow { .. }));
    }

    #[test]
    fn issuing_beyond_the_max_validity_is_rejected() {
        let identity = DualKeyPair::generate();
        let err =
            CapabilityToken::issue(&identity, 1_000, MAX_TOKEN_VALIDITY_SECONDS + 1).unwrap_err();
        assert!(matches!(err, NetError::InvalidValidityWindow { .. }));
    }

    #[test]
    fn exactly_max_validity_is_accepted() {
        let identity = DualKeyPair::generate();
        assert!(CapabilityToken::issue(&identity, 1_000, MAX_TOKEN_VALIDITY_SECONDS).is_ok());
    }

    #[test]
    fn round_trip_bytes_preserves_and_reverifies() {
        let identity = DualKeyPair::generate();
        let token = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        let bytes = token.to_bytes();
        let decoded = CapabilityToken::from_bytes(&bytes).unwrap();
        assert!(decoded.verify(1_000).is_ok());
        assert_eq!(decoded.issued_at(), 1_000);
        assert_eq!(decoded.expires_at(), 4_600);
        assert_eq!(decoded.ed25519_identity(), &identity.ed25519_public_bytes());
    }

    #[test]
    fn tampering_issued_at_after_encoding_fails_verification() {
        let identity = DualKeyPair::generate();
        let token = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        let mut bytes = token.to_bytes();
        // issued_at's 8 BE bytes sit right after magic(4) + ed25519_pub(32)
        // + ml_dsa87_pub_len(2) + ml_dsa87_pub(N). Flip a byte deep enough
        // that it lands inside issued_at regardless of key length by
        // locating it structurally instead of by a hardcoded offset.
        let ml_dsa87_len = u16::from_be_bytes([bytes[4 + 32], bytes[4 + 32 + 1]]) as usize;
        let issued_at_offset = 4 + 32 + 2 + ml_dsa87_len;
        bytes[issued_at_offset] ^= 0xFF;
        let decoded = CapabilityToken::from_bytes(&bytes).unwrap();
        assert!(matches!(
            decoded.verify(1_000).unwrap_err(),
            NetError::SignatureInvalid
        ));
    }

    #[test]
    fn tampering_nonce_after_encoding_fails_verification() {
        let identity = DualKeyPair::generate();
        let token = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        let mut bytes = token.to_bytes();
        let ml_dsa87_len = u16::from_be_bytes([bytes[4 + 32], bytes[4 + 32 + 1]]) as usize;
        // nonce sits after magic + ed25519_pub + ml_dsa87_pub(framed) +
        // issued_at(8) + expires_at(8).
        let nonce_offset = 4 + 32 + 2 + ml_dsa87_len + 8 + 8;
        bytes[nonce_offset] ^= 0xFF;
        let decoded = CapabilityToken::from_bytes(&bytes).unwrap();
        assert!(matches!(
            decoded.verify(1_000).unwrap_err(),
            NetError::SignatureInvalid
        ));
    }

    #[test]
    fn substituting_a_different_signers_public_keys_fails_verification() {
        // A forged token: victim's issue() output, but with the
        // attacker's own dual signature stitched onto claimed keys that
        // still say "victim." Simulated directly by re-signing victim's
        // exact claimed fields with a different keypair, which is
        // exactly what `from_bytes` cannot detect structurally — only
        // `verify`'s signature check catches it.
        let victim = DualKeyPair::generate();
        let attacker = DualKeyPair::generate();
        let victim_token = CapabilityToken::issue(&victim, 1_000, 3_600).unwrap();

        // Build a token claiming victim's public keys but actually
        // signed by the attacker (attacker cannot produce a valid
        // signature over victim's identity without victim's private
        // keys, so this must fail).
        let forged = CapabilityToken::issue(&attacker, 1_000, 3_600).unwrap();
        let mut forged_bytes = forged.to_bytes();
        let victim_bytes = victim_token.to_bytes();
        // Splice victim's public-key region into the attacker-signed
        // token's byte layout (same lengths, since both keys are the
        // same algorithm suite).
        let ml_dsa87_len =
            u16::from_be_bytes([victim_bytes[4 + 32], victim_bytes[4 + 32 + 1]]) as usize;
        let pubkey_region_end = 4 + 32 + 2 + ml_dsa87_len;
        forged_bytes[4..pubkey_region_end].copy_from_slice(&victim_bytes[4..pubkey_region_end]);

        let decoded = CapabilityToken::from_bytes(&forged_bytes).unwrap();
        assert!(matches!(
            decoded.verify(1_000).unwrap_err(),
            NetError::SignatureInvalid
        ));
    }

    #[test]
    fn truncated_bytes_at_every_prefix_length_are_rejected_without_panicking() {
        let identity = DualKeyPair::generate();
        let token = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        let bytes = token.to_bytes();
        for cut in 0..bytes.len() {
            let result = CapabilityToken::from_bytes(&bytes[..cut]);
            assert!(result.is_err(), "cut at {cut} unexpectedly parsed");
        }
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        let identity = DualKeyPair::generate();
        let token = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        let mut bytes = token.to_bytes();
        bytes.push(0xAB);
        let err = CapabilityToken::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, NetError::TrailingData));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let identity = DualKeyPair::generate();
        let token = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        let mut bytes = token.to_bytes();
        bytes[0] = b'X';
        let err = CapabilityToken::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, NetError::BadMagic));
    }

    #[test]
    fn implausible_length_prefix_is_rejected_without_panicking() {
        let identity = DualKeyPair::generate();
        let token = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        let mut bytes = token.to_bytes();
        // Overwrite the ml_dsa87_pub length prefix with an implausibly
        // large value that cannot possibly fit in the remaining bytes.
        bytes[4 + 32] = 0xFF;
        bytes[4 + 32 + 1] = 0xFF;
        let err = CapabilityToken::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            NetError::MalformedLength { .. } | NetError::Truncated
        ));
    }

    #[test]
    fn different_issuances_use_different_nonces() {
        let identity = DualKeyPair::generate();
        let a = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        let b = CapabilityToken::issue(&identity, 1_000, 3_600).unwrap();
        assert_ne!(
            a.to_bytes(),
            b.to_bytes(),
            "issuance must not be deterministic"
        );
    }

    #[test]
    fn issued_at_after_expires_at_is_rejected_at_issuance() {
        // issue()'s own arithmetic (issued_at + validity_seconds) can
        // never itself produce issued_at > expires_at for any valid
        // validity_seconds >= 1, so this exercises the same invariant
        // the way a hand-crafted/adversarial wire token could violate
        // it: construct bytes with issued_at > expires_at directly and
        // confirm `verify` rejects the malformed window rather than
        // e.g. treating "already expired forever" as merely
        // `TokenExpired`.
        let identity = DualKeyPair::generate();
        let token = CapabilityToken::issue(&identity, 5_000, 3_600).unwrap(); // expires 8600
        let mut bytes = token.to_bytes();
        let ml_dsa87_len = u16::from_be_bytes([bytes[4 + 32], bytes[4 + 32 + 1]]) as usize;
        let issued_at_offset = 4 + 32 + 2 + ml_dsa87_len;
        let expires_at_offset = issued_at_offset + 8;
        // Set issued_at to something after expires_at (8_600), without
        // touching expires_at itself, then re-derive: since this also
        // invalidates the signature, we instead directly assert the
        // structural check fires on `verify` for the byte-identical
        // scenario check via the (still-valid-signature) case is
        // impossible to construct without the signing key; the
        // structural ordering check must therefore run *before* or
        // independently of the signature check for this to be testable
        // at all without forging a signature. See implementation:
        // ordering is validated against the token's own decoded fields
        // prior to (or regardless of) signature verification, which is
        // exactly why this test asserts against a tampered-and-thus-
        // signature-invalid token too: whichever error fires first, it
        // must not be `Ok(())`.
        bytes[issued_at_offset..issued_at_offset + 8].copy_from_slice(&20_000u64.to_be_bytes());
        let _ = expires_at_offset; // structural offset retained for clarity
        let decoded = CapabilityToken::from_bytes(&bytes).unwrap();
        assert!(decoded.verify(20_100).is_err());
    }

    #[test]
    fn genuinely_signed_token_with_inverted_window_is_rejected_by_structural_check() {
        // Assertion-strength check finding: every other "inverted
        // window" test in this file tampers `issued_at` post-encoding,
        // which *also* breaks the signature (the signature covers
        // `issued_at`), so `verify`'s signature check — which now runs
        // first — already rejects those cases on its own. That leaves
        // the `self.issued_at > self.expires_at` structural check in
        // `verify` provably untested: nothing proved it does
        // independent work rather than being dead code shadowed by the
        // signature check. `CapabilityToken::issue` itself can never
        // produce such a token (it rejects the window before signing),
        // so this test bypasses `issue` entirely and hand-builds a
        // token whose signature is genuinely valid over an inverted
        // window, to prove the structural check independently catches
        // what the signature check cannot.
        let identity = DualKeyPair::generate();
        let issued_at = 20_000u64;
        let expires_at = 10_000u64; // inverted: issued_at > expires_at
        let nonce = [0x42u8; NONCE_LEN];
        let ed25519_pub = identity.ed25519_public_bytes();
        let ml_dsa87_pub = identity.ml_dsa87_public_bytes();
        let payload = signing_payload(&ed25519_pub, &ml_dsa87_pub, issued_at, expires_at, &nonce);
        let signature = identity.sign(&payload);

        let token = CapabilityToken {
            ed25519_pub,
            ml_dsa87_pub,
            issued_at,
            expires_at,
            nonce,
            signature,
        };

        assert!(matches!(
            token.verify(15_000).unwrap_err(),
            NetError::InvalidValidityWindow { .. }
        ));
    }
}
