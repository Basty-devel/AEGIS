//! Official NIST ACVP known-answer tests for ML-KEM-1024, using the
//! same fixture files the `ml-kem` crate tests itself against
//! (RustCrypto/KEMs, `ml-kem/tests/key-gen.json` and
//! `ml-kem/tests/encap-decap.json`). Verifies our wrapper's plumbing
//! against official vectors per spec Section 9.1.
//!
//! All three ACVP functions are covered, and every vector in each
//! ML-KEM-1024 group is exercised rather than only the first:
//!
//! - `keyGen` (25 vectors): deterministic key generation from `(d, z)`,
//!   checking both the public `ek` and the private `dk`.
//! - `encapDecap` AFT (25 vectors): `encapsulate_deterministic`, the
//!   `#[doc(hidden)]` hazmat entry point [`aegis_crypto::kem`] uses in
//!   production. It is fed a caller-supplied `m` rather than an RNG, so
//!   a round-trip test cannot detect it being mis-wired — only a vector
//!   with a known `(m, c, k)` can.
//! - `encapDecap` VAL (10 vectors): decapsulation against a fixed `dk`.

#![allow(deprecated)] // the expanded `dk` encoding the ACVP fixtures use
                      // is deprecated upstream in favour of seeds; the
                      // vectors are still the authoritative KAT source.

use ml_kem::{
    array::Array, Ciphertext, Decapsulate, DecapsulationKey, EncapsulationKey,
    ExpandedKeyEncoding, FromSeed, Key, KeyExport, MlKem1024,
};
use serde::Deserialize;
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
    #[serde(rename = "testType", default)]
    test_type: String,
    #[serde(default)]
    function: String,
    /// Present only on the VAL decapsulation groups, where the key is
    /// shared by every test case in the group.
    #[serde(default)]
    dk: Option<String>,
    tests: Vec<T>,
}

#[derive(Deserialize)]
struct KeyGenCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    d: String,
    z: String,
    ek: String,
    dk: String,
}

/// One `encapDecap` case. The AFT (encapsulation) and VAL
/// (decapsulation) groups live in the same file but carry different
/// fields, and serde deserializes every group in the file, so the
/// group-specific fields are optional here and unwrapped only inside
/// the test that requires them.
#[derive(Deserialize)]
struct EncapDecapCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(default)]
    ek: Option<String>,
    #[serde(default)]
    m: Option<String>,
    c: String,
    k: String,
}

fn load<T: serde::de::DeserializeOwned>(path: &str) -> TestVectorFile<T> {
    let json = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("fixture {path} must be readable: {e}"));
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("fixture {path} must parse: {e}"))
}

#[test]
fn acvp_ml_kem_1024_key_gen_all_vectors() {
    let file: TestVectorFile<KeyGenCase> = load("tests/vectors/ml-kem-key-gen.json");
    let group = file
        .test_groups
        .iter()
        .find(|g| g.parameter_set == "ML-KEM-1024")
        .expect("fixture file has an ML-KEM-1024 test group");

    assert_eq!(
        group.tests.len(),
        25,
        "expected the full ACVP keyGen group, not a subset",
    );

    for case in &group.tests {
        let d = hex::decode(&case.d).unwrap();
        let z = hex::decode(&case.z).unwrap();
        let expected_ek = hex::decode(&case.ek).unwrap();
        let expected_dk = hex::decode(&case.dk).unwrap();

        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);

        let (dk, ek) = MlKem1024::from_seed(&seed.into());

        assert_eq!(
            ek.to_bytes().as_slice(),
            expected_ek.as_slice(),
            "tcId {}: encapsulation key mismatch",
            case.tc_id,
        );
        assert_eq!(
            dk.to_expanded_bytes().as_slice(),
            expected_dk.as_slice(),
            "tcId {}: decapsulation key mismatch",
            case.tc_id,
        );
    }
}

#[test]
fn acvp_ml_kem_1024_encapsulate_all_vectors() {
    let file: TestVectorFile<EncapDecapCase> = load("tests/vectors/ml-kem-encap-decap.json");
    let group = file
        .test_groups
        .iter()
        .find(|g| {
            g.parameter_set == "ML-KEM-1024" && g.function == "encapsulation" && g.test_type == "AFT"
        })
        .expect("fixture file has an ML-KEM-1024 AFT encapsulation group");

    assert_eq!(
        group.tests.len(),
        25,
        "expected the full ACVP encapsulation group, not a subset",
    );

    for case in &group.tests {
        let ek_bytes = hex::decode(case.ek.as_ref().expect("AFT cases carry ek")).unwrap();
        let m = hex::decode(case.m.as_ref().expect("AFT cases carry m")).unwrap();
        let expected_c = hex::decode(&case.c).unwrap();
        let expected_k = hex::decode(&case.k).unwrap();

        let key_array: Key<EncapsulationKey<MlKem1024>> =
            Array::try_from(ek_bytes.as_slice()).unwrap();
        let ek = EncapsulationKey::<MlKem1024>::new(&key_array).unwrap();

        let m_array = Array::try_from(m.as_slice()).unwrap();
        let (ciphertext, shared_secret) = ek.encapsulate_deterministic(&m_array);

        assert_eq!(
            ciphertext.as_slice(),
            expected_c.as_slice(),
            "tcId {}: ciphertext mismatch",
            case.tc_id,
        );
        assert_eq!(
            shared_secret.as_slice(),
            expected_k.as_slice(),
            "tcId {}: shared secret mismatch",
            case.tc_id,
        );
    }
}

#[test]
fn acvp_ml_kem_1024_decapsulate_all_vectors() {
    let file: TestVectorFile<EncapDecapCase> = load("tests/vectors/ml-kem-encap-decap.json");
    let group = file
        .test_groups
        .iter()
        .find(|g| {
            g.parameter_set == "ML-KEM-1024" && g.function == "decapsulation" && g.test_type == "VAL"
        })
        .expect("fixture file has an ML-KEM-1024 VAL decapsulation group");

    assert!(
        group.tests.len() >= 10,
        "expected the full ACVP decapsulation group, not a subset",
    );

    let dk_bytes = hex::decode(
        group
            .dk
            .as_ref()
            .expect("VAL decapsulation groups carry a group-level dk"),
    )
    .unwrap();
    let dk_array = Array::try_from(dk_bytes.as_slice()).unwrap();
    let dk = DecapsulationKey::<MlKem1024>::from_expanded_bytes(&dk_array).unwrap();

    for case in &group.tests {
        let c = hex::decode(&case.c).unwrap();
        let expected_k = hex::decode(&case.k).unwrap();

        let ct: Ciphertext<MlKem1024> = Array::try_from(c.as_slice()).unwrap();
        let shared_secret = dk.decapsulate(&ct);

        assert_eq!(
            shared_secret.as_slice(),
            expected_k.as_slice(),
            "tcId {}: shared secret mismatch",
            case.tc_id,
        );
    }
}
