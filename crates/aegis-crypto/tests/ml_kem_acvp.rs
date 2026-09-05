//! Official NIST ACVP key-generation KAT for ML-KEM-1024, filtered from
//! the same fixture file the `ml-kem` crate tests itself against
//! (RustCrypto/KEMs, ml-kem/tests/key-gen.json). Verifies our wrapper's
//! deterministic key generation against an official KAT per spec
//! Section 9.1.

use ml_kem::{FromSeed, KeyExport, MlKem1024};
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
