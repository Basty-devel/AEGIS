//! brainpoolP512r1 ECDH. See AEGIS.Plan.V0.2.md Section 2.
//!
//! Uses `bp512-nestler` (see this crate's Cargo.toml and the workspace
//! root's `[patch.crates-io]` block) since no brainpool512r1
//! implementation exists in the mainline RustCrypto ecosystem as of
//! this writing. Domain parameters: RFC 5639 Section 3.7.
//!
//! # Dependency risk — read before relying on this module
//!
//! `bp512-nestler` is the least-trustworthy dependency in this crate
//! and the only primitive here not backed by a mainline RustCrypto
//! implementation. Specifically:
//!
//! - Version **0.1.2**, a pre-1.0 single-author crate with no
//!   third-party cryptographic audit.
//! - Licensed **PolyForm-Noncommercial-1.0.0**, which is an unresolved
//!   tension with AEGIS's own (as yet undecided) license — a
//!   noncommercial-only dependency constrains what AEGIS itself can be
//!   licensed as. Flagged for the licensing decision, not settled here.
//! - Published under the **same GitHub organisation as AEGIS itself**,
//!   so it does not represent independent third-party review the way
//!   the RustCrypto dependencies do.
//! - It requires a workspace-level `[patch.crates-io]` override of
//!   `hybrid-array`. That patch is not scoped to this module: it also
//!   applies to `ml-kem`, `ml-dsa`, `aes-gcm`, and
//!   `chacha20poly1305`, all of which depend on `hybrid-array`.
//!
//! The mitigation in this module is the RFC 7027 Appendix A.3
//! known-answer test below, which pins the curve arithmetic to
//! published vectors. A pure round-trip test cannot do that: two
//! parties using *consistently wrong* curve constants still agree with
//! each other.

use crate::error::CryptoError;
use bp512_nestler::BrainpoolP512r1;
use elliptic_curve::{PublicKey, SecretKey};
use zeroize::{Zeroize, Zeroizing};

/// Byte length of a brainpoolP512r1 ECDH shared secret (the
/// x-coordinate of the shared point, RFC 5639 Section 3.7 field size).
pub const BRAINPOOL512_SHARED_SECRET_LEN: usize = 64;

/// A brainpoolP512r1 private scalar.
///
/// The inner [`elliptic_curve::SecretKey`] implements `ZeroizeOnDrop`
/// unconditionally (`elliptic-curve` takes `zeroize` as a mandatory,
/// non-optional dependency and implements `Drop` for `SecretKey<C>` in
/// `secret_key.rs`), so this wrapper needs no zeroization logic of its
/// own — verified by source inspection of elliptic-curve 0.14.1.
pub struct Brainpool512SecretKey(SecretKey<BrainpoolP512r1>);

impl Brainpool512SecretKey {
    /// Generate a fresh private scalar from OS randomness.
    ///
    /// # Panics
    ///
    /// Panics if the operating system RNG fails. This is a deliberate
    /// fail-closed panic, not an oversight: the condition is not
    /// attacker-controlled (no wire data reaches it), and the only
    /// alternative to aborting would be continuing with unknown or
    /// low-entropy key material, which is strictly worse than stopping.
    pub fn generate() -> Self {
        loop {
            let mut bytes = elliptic_curve::FieldBytes::<BrainpoolP512r1>::default();
            getrandom::fill(&mut bytes).expect("OS RNG failure");
            let candidate = SecretKey::<BrainpoolP512r1>::from_bytes(&bytes);
            // Zeroize the raw sample whether or not it was accepted:
            // an accepted sample is still live key material held in a
            // second place, and a rejected one is a near-miss scalar
            // that must not be left on the stack either.
            bytes.as_mut_slice().zeroize();
            if let Ok(secret) = candidate {
                return Self(secret);
            }
            // Rejection sampling: retry on the astronomically rare case
            // the raw bytes aren't a valid nonzero scalar below the
            // curve order.
        }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.0.public_key().to_sec1_bytes().to_vec()
    }
}

/// Compute the brainpoolP512r1 ECDH shared secret between `secret` and
/// the peer public key encoded in `peer_public_bytes` (SEC1).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPeerPublicKey`] if `peer_public_bytes`
/// is not a valid SEC1 encoding of a point on brainpoolP512r1. These
/// bytes arrive straight off the wire, so this must never panic.
///
/// The returned secret is wrapped in [`Zeroizing`] so it is wiped when
/// the caller drops it — `elliptic_curve::ecdh::SharedSecret` zeroizes
/// itself, and copying its bytes out into a bare array would defeat
/// that.
pub fn brainpool512_diffie_hellman(
    secret: &Brainpool512SecretKey,
    peer_public_bytes: &[u8],
) -> Result<Zeroizing<[u8; BRAINPOOL512_SHARED_SECRET_LEN]>, CryptoError> {
    let peer_public = PublicKey::<BrainpoolP512r1>::from_sec1_bytes(peer_public_bytes)
        .map_err(|_| CryptoError::InvalidPeerPublicKey)?;
    let shared = secret.0.diffie_hellman(&peer_public);
    let mut out = Zeroizing::new([0u8; BRAINPOOL512_SHARED_SECRET_LEN]);
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C2 regression guard — see the equivalent test in `kem.rs`.
    /// `elliptic_curve::SecretKey` zeroizes unconditionally (zeroize is
    /// a mandatory dependency of that crate), so this pins a property
    /// we rely on rather than one we had to switch on.
    #[test]
    fn secret_key_and_shared_secret_zeroize() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretKey<BrainpoolP512r1>>();
        assert_zeroize_on_drop::<elliptic_curve::ecdh::SharedSecret<BrainpoolP512r1>>();

        fn assert_zeroizing<T: zeroize::Zeroize>(_: &Zeroizing<T>) {}
        let a = Brainpool512SecretKey::generate();
        let b = Brainpool512SecretKey::generate();
        assert_zeroizing(&brainpool512_diffie_hellman(&a, &b.public_key_bytes()).unwrap());
    }

    /// RFC 7027 Appendix A.3 ("512-Bit Curve", brainpoolP512r1), the
    /// published ECDH example values, transcribed from the RFC text at
    /// <https://www.rfc-editor.org/rfc/rfc7027.txt>. Line breaks in the
    /// RFC's hex are joined here; each value is 64 bytes.
    ///
    /// This is the only test in this module that can catch wrong curve
    /// constants in the unaudited `bp512-nestler` dependency — the
    /// round-trip tests below agree with themselves regardless.
    mod rfc7027_a3 {
        pub const DA: &str = "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59\
                              B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422";
        pub const X_QA: &str = "0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C614999\
                                9397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD09FD";
        pub const Y_QA: &str = "72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472A0FCE\
                                F3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147FDE7";
        pub const DB: &str = "230E18E1BCC88A362FA54E4EA3902009292F7F8033624FD471B5D8ACE49D12CF\
                              ABBC19963DAB8E2F1EBA00BFFB29E4D72D13F2224562F405CB80503666B25429";
        pub const X_QB: &str = "9D45F66DE5D67E2E6DB6E93A59CE0BB48106097FF78A081DE781CDB31FCE8CCB\
                                AAEA8DD4320C4119F1E9CD437A2EAB3731FA9668AB268D871DEDA55A5473199F";
        pub const Y_QB: &str = "2FDC313095BCDD5FB3A91636F07A959C8E86B5636A1E930E8396049CB481961D\
                                365CC11453A06C719835475B12CB52FC3C383BCE35E27EF194512B71876285FA";
        pub const X_Z: &str = "A7927098655F1F9976FA50A9D566865DC530331846381C87256BAF3226244B76\
                               D36403C024D7BBF0AA0803EAFF405D3D24F11A9B5C0BEF679FE1454B21C4CD1F";
    }

    /// Build the uncompressed SEC1 encoding (`0x04 || x || y`) of a
    /// public key from the RFC's separate coordinate hex strings.
    fn uncompressed_sec1(x_hex: &str, y_hex: &str) -> Vec<u8> {
        let x = hex::decode(x_hex).unwrap();
        let y = hex::decode(y_hex).unwrap();
        assert_eq!(x.len(), 64, "RFC 7027 x-coordinate is 64 bytes");
        assert_eq!(y.len(), 64, "RFC 7027 y-coordinate is 64 bytes");
        let mut out = Vec::with_capacity(1 + x.len() + y.len());
        out.push(0x04);
        out.extend_from_slice(&x);
        out.extend_from_slice(&y);
        out
    }

    fn secret_key_from_hex(hex_str: &str) -> Brainpool512SecretKey {
        let bytes = hex::decode(hex_str).unwrap();
        assert_eq!(bytes.len(), 64, "RFC 7027 private scalar is 64 bytes");
        let field_bytes = elliptic_curve::FieldBytes::<BrainpoolP512r1>::try_from(&bytes[..])
            .expect("64 bytes is the brainpoolP512r1 field size");
        Brainpool512SecretKey(
            SecretKey::<BrainpoolP512r1>::from_bytes(&field_bytes)
                .expect("RFC 7027 scalar is a valid private key"),
        )
    }

    /// Known-answer test against RFC 7027 Appendix A.3. Verifies three
    /// independent things about `bp512-nestler`'s curve arithmetic:
    /// scalar multiplication of the base point (dA -> qA, dB -> qB) and
    /// the ECDH shared x-coordinate from both directions.
    #[test]
    fn brainpool512_official_kat_rfc7027() {
        let a = secret_key_from_hex(rfc7027_a3::DA);
        let b = secret_key_from_hex(rfc7027_a3::DB);

        let expected_qa = uncompressed_sec1(rfc7027_a3::X_QA, rfc7027_a3::Y_QA);
        let expected_qb = uncompressed_sec1(rfc7027_a3::X_QB, rfc7027_a3::Y_QB);

        // dA * G == qA and dB * G == qB. Compared as parsed points so
        // the assertion is independent of SEC1 point-compression choice.
        assert_eq!(
            a.0.public_key(),
            PublicKey::<BrainpoolP512r1>::from_sec1_bytes(&expected_qa).unwrap(),
            "dA * G must equal the RFC's qA",
        );
        assert_eq!(
            b.0.public_key(),
            PublicKey::<BrainpoolP512r1>::from_sec1_bytes(&expected_qb).unwrap(),
            "dB * G must equal the RFC's qB",
        );

        let expected_z = hex::decode(rfc7027_a3::X_Z).unwrap();
        let z_ab = brainpool512_diffie_hellman(&a, &expected_qb).unwrap();
        let z_ba = brainpool512_diffie_hellman(&b, &expected_qa).unwrap();

        assert_eq!(z_ab.as_slice(), expected_z.as_slice(), "dA * qB != RFC x_Z");
        assert_eq!(z_ba.as_slice(), expected_z.as_slice(), "dB * qA != RFC x_Z");
    }

    #[test]
    fn both_sides_derive_the_same_shared_secret() {
        let alice = Brainpool512SecretKey::generate();
        let bob = Brainpool512SecretKey::generate();

        let alice_shared = brainpool512_diffie_hellman(&alice, &bob.public_key_bytes()).unwrap();
        let bob_shared = brainpool512_diffie_hellman(&bob, &alice.public_key_bytes()).unwrap();

        assert_eq!(*alice_shared, *bob_shared);
    }

    #[test]
    fn malformed_peer_public_key_is_rejected_without_panicking() {
        let alice = Brainpool512SecretKey::generate();

        for malformed in [
            &b""[..],
            &b"not a point"[..],
            &[0x04u8; 129][..],
            &[0xFFu8; 65][..],
        ] {
            assert_eq!(
                brainpool512_diffie_hellman(&alice, malformed).unwrap_err(),
                CryptoError::InvalidPeerPublicKey,
                "malformed peer key must return an error, not panic",
            );
        }
    }

    #[test]
    fn different_peers_give_different_shared_secrets() {
        let alice = Brainpool512SecretKey::generate();
        let bob = Brainpool512SecretKey::generate();
        let carol = Brainpool512SecretKey::generate();

        let alice_bob = brainpool512_diffie_hellman(&alice, &bob.public_key_bytes()).unwrap();
        let alice_carol = brainpool512_diffie_hellman(&alice, &carol.public_key_bytes()).unwrap();

        assert_ne!(*alice_bob, *alice_carol);
    }
}
