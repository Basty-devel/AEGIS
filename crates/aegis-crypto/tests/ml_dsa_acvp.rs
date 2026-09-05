//! Official NIST ACVP known-answer tests for ML-DSA-87, using the same
//! fixture files the `ml-dsa` crate tests itself against
//! (RustCrypto/signatures, `ml-dsa/tests/{key-gen,sig-gen,sig-ver}.json`).
//! Verifies our wrapper's plumbing against official vectors per spec
//! Section 9.1.
//!
//! All three ACVP functions are covered, and every vector in each
//! ML-DSA-87 group is exercised rather than only the first:
//!
//! - `keyGen` (25 vectors): deterministic key generation from a seed,
//!   checking both the public `pk` and the private `sk`.
//! - `sigGen` (10 vectors, deterministic group): signing a known
//!   message with a known key must reproduce the exact signature bytes.
//! - `sigVer` (15 vectors, 3 valid / 12 invalid), covering the four
//!   official ways a signature is made invalid: modified message,
//!   modified signature, `z` too large, and too many hints.
//!
//! # ACVP tests the *internal* functions
//!
//! FIPS 204 splits signing into `ML-DSA.Sign(sk, M, ctx)`, which
//! prepends the domain separator `M' = 0x00 || len(ctx) || ctx || M`,
//! and `ML-DSA.Sign_internal(sk, M', rnd)`, which does not. The ACVP
//! `sigGen`/`sigVer` vectors are generated against the **internal**
//! functions, so the two tests below call `sign_internal` and
//! `verify_internal` — matching how the `ml-dsa` crate itself consumes
//! these same files.
//!
//! Production code here (`DualKeyPair::sign`, `verify_dual`) correctly
//! uses the *external* API with an empty context, which is the right
//! choice for signing protocol messages. Two further tests bridge the
//! gap so the ACVP vectors constrain the production path and not just
//! the dependency's internals:
//! `external_sign_matches_acvp_validated_internal_signing` pins the
//! external API to the internal one through FIPS 204's `M'` rule, and
//! `verify_dual_accepts_a_signature_under_an_acvp_key` runs
//! `verify_dual` over official ACVP key material.
//!
//! `keyGen` and `sigGen` exercise the underlying `ml_dsa` crate
//! directly rather than our `DualKeyPair` wrapper, because production
//! code always generates from secure randomness and `DualKeyPair`
//! therefore intentionally has no seed-based or byte-based constructor.

#![allow(deprecated)] // the expanded `sk` encoding the ACVP fixtures use
                      // is deprecated upstream in favour of seeds; the
                      // vectors are still the authoritative KAT source.

use aegis_crypto::signature::{verify_dual, DualSignature};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa87,
    Signature, SigningKey, VerifyingKey, B32,
};
use serde::Deserialize;
// Imported from `signature` directly rather than relying on either
// signing crate's re-export, so this file keeps compiling if one of
// them stops re-exporting the trait.
use signature::{Keypair, Signer as _};
use std::fs;

#[derive(Deserialize)]
struct TestVectorFile<T> {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup<T>>,
}

#[derive(Deserialize)]
struct TestGroup<T> {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    /// `sigGen` splits ML-DSA-87 into a deterministic and a hedged
    /// group; only the deterministic one has a fixed expected output.
    #[serde(default)]
    deterministic: Option<bool>,
    /// `sigVer` carries one verifying key for the whole group.
    #[serde(default)]
    pk: Option<String>,
    tests: Vec<T>,
}

#[derive(Deserialize)]
struct KeyGenCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    seed: String,
    pk: String,
    sk: String,
}

#[derive(Deserialize)]
struct SigGenCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    sk: String,
    message: String,
    signature: String,
}

#[derive(Deserialize)]
struct SigVerCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "testPassed")]
    test_passed: bool,
    message: String,
    signature: String,
    reason: String,
}

fn load<T: serde::de::DeserializeOwned>(path: &str) -> TestVectorFile<T> {
    let json =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("fixture {path} must be readable: {e}"));
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("fixture {path} must parse: {e}"))
}

fn ml_dsa_87_group<T>(file: &TestVectorFile<T>) -> &TestGroup<T> {
    file.test_groups
        .iter()
        .find(|g| g.parameter_set == "ML-DSA-87")
        .expect("fixture file has an ML-DSA-87 test group")
}

#[test]
fn acvp_ml_dsa_87_key_gen_all_vectors() {
    let file: TestVectorFile<KeyGenCase> = load("tests/vectors/ml-dsa-key-gen.json");
    let group = ml_dsa_87_group(&file);

    assert_eq!(
        group.tests.len(),
        25,
        "expected the full ACVP keyGen group, not a subset",
    );

    for case in &group.tests {
        let seed_bytes = hex::decode(&case.seed).unwrap();
        let expected_pk = hex::decode(&case.pk).unwrap();
        let expected_sk = hex::decode(&case.sk).unwrap();

        let seed = seed_bytes.as_slice().try_into().expect("32-byte seed");
        let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);

        let encoded_pk: EncodedVerifyingKey<MlDsa87> = signing_key.verifying_key().encode();
        assert_eq!(
            encoded_pk.as_slice(),
            expected_pk.as_slice(),
            "tcId {}: verifying key mismatch",
            case.tc_id,
        );
        assert_eq!(
            signing_key.expanded_key().to_expanded().as_slice(),
            expected_sk.as_slice(),
            "tcId {}: signing key mismatch",
            case.tc_id,
        );
    }
}

#[test]
fn acvp_ml_dsa_87_sig_gen_all_deterministic_vectors() {
    let file: TestVectorFile<SigGenCase> = load("tests/vectors/ml-dsa-sig-gen.json");
    let group = file
        .test_groups
        .iter()
        .find(|g| g.parameter_set == "ML-DSA-87" && g.deterministic == Some(true))
        .expect("fixture file has a deterministic ML-DSA-87 sigGen group");

    assert!(
        group.tests.len() >= 10,
        "expected the full ACVP deterministic sigGen group, not a subset",
    );

    for case in &group.tests {
        let sk_bytes = hex::decode(&case.sk).unwrap();
        let message = hex::decode(&case.message).unwrap();
        let expected_signature = hex::decode(&case.signature).unwrap();

        let sk_array = ExpandedSigningKeyBytes::<MlDsa87>::try_from(sk_bytes.as_slice())
            .expect("ACVP sk is the expanded ML-DSA-87 signing key size");
        let signing_key = ExpandedSigningKey::<MlDsa87>::from_expanded(&sk_array);

        // Deterministic group: rnd is the all-zero B32, and the message
        // is fed to Sign_internal verbatim (no M' prefix) — see this
        // file's header.
        let signature = signing_key.sign_internal(&[&message], &B32::default());

        assert_eq!(
            signature.encode().as_slice(),
            expected_signature.as_slice(),
            "tcId {}: signature mismatch",
            case.tc_id,
        );
    }
}

#[test]
fn acvp_ml_dsa_87_sig_ver_all_vectors() {
    let file: TestVectorFile<SigVerCase> = load("tests/vectors/ml-dsa-sig-ver.json");
    let group = ml_dsa_87_group(&file);

    assert!(
        group.tests.len() >= 15,
        "expected the full ACVP sigVer group, not a subset",
    );

    let pk_bytes =
        hex::decode(group.pk.as_ref().expect("sigVer groups carry a group-level pk")).unwrap();
    let encoded_vk = EncodedVerifyingKey::<MlDsa87>::try_from(pk_bytes.as_slice()).unwrap();
    let vk = VerifyingKey::<MlDsa87>::decode(&encoded_vk);

    let mut valid_seen = 0usize;
    let mut invalid_seen = 0usize;

    for case in &group.tests {
        let message = hex::decode(&case.message).unwrap();
        let signature_bytes = hex::decode(&case.signature).unwrap();

        // A signature that fails to decode is simply invalid — the same
        // shape `verify_dual` uses for its own decode guards.
        let verified = EncodedSignature::<MlDsa87>::try_from(signature_bytes.as_slice())
            .ok()
            .and_then(|encoded| Signature::<MlDsa87>::decode(&encoded))
            .is_some_and(|sig| vk.verify_internal(&message, &sig));

        assert_eq!(
            verified, case.test_passed,
            "tcId {} ({}): verification disagreed with the ACVP expected result",
            case.tc_id, case.reason,
        );

        if case.test_passed {
            valid_seen += 1;
        } else {
            invalid_seen += 1;
        }
    }

    // Guard against a fixture that is silently all-negative (which a
    // verifier stuck at `false` would also satisfy) or all-positive.
    assert!(valid_seen > 0, "fixture must contain valid signatures");
    assert!(invalid_seen > 0, "fixture must contain invalid signatures");
}

/// Bridges the ACVP-validated internal signing function to the external
/// API `DualKeyPair::sign` actually calls.
///
/// FIPS 204 Algorithm 2 defines `ML-DSA.Sign(sk, M, ctx)` as
/// `Sign_internal(sk, M', rnd)` with `M' = 0x00 || len(ctx) || ctx || M`.
/// With the empty context this crate uses, `M'` is `0x00 || 0x00 || M`.
/// Asserting that equality over official ACVP key material is what makes
/// the `sigGen` vectors above constrain our production signing path.
#[test]
fn external_sign_matches_acvp_validated_internal_signing() {
    let file: TestVectorFile<KeyGenCase> = load("tests/vectors/ml-dsa-key-gen.json");
    let group = ml_dsa_87_group(&file);

    let message = b"hello aegis";

    for case in group.tests.iter().take(3) {
        let seed_bytes = hex::decode(&case.seed).unwrap();
        let seed = seed_bytes.as_slice().try_into().expect("32-byte seed");
        let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);

        // What `DualKeyPair::sign` does.
        let external = signing_key.sign(message).encode();

        // The same thing spelled out through Sign_internal, with the
        // empty-context M' prefix applied by hand.
        let internal = signing_key
            .expanded_key()
            .sign_internal(&[&[0x00, 0x00], message], &B32::default())
            .encode();

        assert_eq!(
            external.as_slice(),
            internal.as_slice(),
            "tcId {}: Signer::sign must equal Sign_internal over 0x00 || 0x00 || M",
            case.tc_id,
        );
    }
}

/// Runs this crate's own `verify_dual` over official ACVP key material,
/// so the production verification path is exercised against vectors and
/// not only against keys it generated itself.
#[test]
fn verify_dual_accepts_a_signature_under_an_acvp_key() {
    let file: TestVectorFile<KeyGenCase> = load("tests/vectors/ml-dsa-key-gen.json");
    let group = ml_dsa_87_group(&file);

    let message = b"hello aegis";
    let ed25519 = Ed25519SigningKey::from_bytes(&[7u8; 32]);
    let ed25519_pub = ed25519.verifying_key().to_bytes();

    for case in group.tests.iter().take(3) {
        let seed_bytes = hex::decode(&case.seed).unwrap();
        let seed = seed_bytes.as_slice().try_into().expect("32-byte seed");
        let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);

        // The verifying key comes from the fixture rather than from our
        // own encoding of it, so a mis-encoded public key fails here.
        let ml_dsa87_pub = hex::decode(&case.pk).unwrap();

        let sig = DualSignature {
            ed25519: ed25519.sign(message).to_bytes(),
            ml_dsa87: signing_key.sign(message).encode().to_vec(),
        };

        assert!(
            verify_dual(&ed25519_pub, &ml_dsa87_pub, message, &sig),
            "tcId {}: verify_dual must accept a valid signature under the ACVP key",
            case.tc_id,
        );

        // And must reject the same signature over a different message.
        assert!(!verify_dual(
            &ed25519_pub,
            &ml_dsa87_pub,
            b"goodbye aegis",
            &sig
        ));
    }
}
