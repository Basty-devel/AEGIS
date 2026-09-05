//! Official NIST ACVP key-generation KAT for ML-DSA-87, filtered from
//! the same fixture file the `ml-dsa` crate tests itself against
//! (RustCrypto/signatures, ml-dsa/tests/key-gen.json). Verifies
//! deterministic key generation against an official KAT per spec
//! Section 9.1. This exercises the underlying `ml_dsa` crate directly
//! (seed-based generation), not our `DualKeyPair` wrapper — production
//! code always generates from secure randomness, never a fixed seed,
//! so `DualKeyPair` intentionally has no seed-based constructor.

use ml_dsa::{EncodedVerifyingKey, MlDsa87, SigningKey};
use serde::Deserialize;
use signature::Keypair;
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
    seed: String,
    pk: String,
}

#[test]
fn acvp_ml_dsa_87_key_gen() {
    let json = fs::read_to_string("tests/vectors/ml-dsa-key-gen.json").unwrap();
    let file: TestVectorFile = serde_json::from_str(&json).unwrap();

    let group = file
        .test_groups
        .iter()
        .find(|g| g.parameter_set == "ML-DSA-87")
        .expect("fixture file has an ML-DSA-87 test group");
    let case = &group.tests[0];

    let seed_bytes = hex::decode(&case.seed).unwrap();
    let expected_pk = hex::decode(&case.pk).unwrap();

    let seed = seed_bytes.as_slice().try_into().expect("32-byte seed");
    let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);
    let verifying_key = signing_key.verifying_key();

    let encoded: EncodedVerifyingKey<MlDsa87> = verifying_key.encode();
    assert_eq!(encoded.as_slice(), expected_pk.as_slice());
}
