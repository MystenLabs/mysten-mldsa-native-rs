// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Mutation-driven ML-DSA-65 vectors from the October 2026 review of mldsa-native and
//! noble-post-quantum. Each invalid case targets one FIPS 204 check. Rerun on every re-pin.

use mysten_mldsa_native_rs::{
    Error, Signature, SigningKeySeed, VerifyingKey, MAX_CONTEXT_LENGTH, RND_LENGTH,
};
use serde::Deserialize;

const VERIFY: &str = include_str!("vectors/forged/mldsa_65_verify_forged_test.json");
const SIGN_SEED: &str = include_str!("vectors/forged/mldsa_65_sign_seed_forged_test.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestFile<G> {
    number_of_tests: usize,
    test_groups: Vec<G>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyGroup {
    public_key: String,
    tests: Vec<VerifyTest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyTest {
    tc_id: u32,
    comment: String,
    msg: String,
    #[serde(default)]
    ctx: String,
    sig: String,
    result: String,
    flags: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignGroup {
    private_seed: String,
    public_key: String,
    tests: Vec<SignTest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignTest {
    tc_id: u32,
    comment: String,
    msg: String,
    #[serde(default)]
    ctx: String,
    rnd: Option<String>,
    sig: String,
    result: String,
    flags: Vec<String>,
}

fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("vector fields are hex")
}

fn is_valid(result: &str) -> bool {
    match result {
        "valid" => true,
        "invalid" => false,
        other => panic!("unexpected result {other:?}"),
    }
}

// Invalid cases with oversized contexts fail before reaching C; all others must return
// InvalidSignature.
fn expected_error(ctx: &[u8]) -> Error {
    if ctx.len() > MAX_CONTEXT_LENGTH {
        Error::ContextTooLong
    } else {
        Error::InvalidSignature
    }
}

#[test]
fn forged_verify() {
    let file: TestFile<VerifyGroup> = serde_json::from_str(VERIFY).unwrap();
    assert_eq!(file.number_of_tests, 787, "vector set changed shape");
    let mut seen = 0;

    for group in &file.test_groups {
        // FIPS 204 has no public key validation, so the `ZeroPublicKey` groups (t1 = 0)
        // parse and their signatures verify; the vectors mark those cases valid.
        let vk = VerifyingKey::from_bytes(&bytes(&group.public_key)).expect("public key parse");

        for t in &group.tests {
            seen += 1;
            let label = format!("tc {} ({})", t.tc_id, t.comment);
            let sig = Signature::from_bytes(&bytes(&t.sig))
                .unwrap_or_else(|e| panic!("{label}: signature parse: {e:?}"));

            let ctx = bytes(&t.ctx);
            let got = vk.verify(&bytes(&t.msg), &ctx, &sig);
            if is_valid(&t.result) {
                assert_eq!(got, Ok(()), "{label}: valid signature rejected");
            } else {
                assert_eq!(got, Err(expected_error(&ctx)), "{label}: {:?}", t.flags);
            }
        }
    }
    assert_eq!(
        seen, file.number_of_tests,
        "vector count differs from the header"
    );
}

#[test]
fn forged_sign_seed() {
    let file: TestFile<SignGroup> = serde_json::from_str(SIGN_SEED).unwrap();
    assert_eq!(file.number_of_tests, 36, "vector set changed shape");
    let mut seen = 0;

    for group in &file.test_groups {
        let seed = SigningKeySeed::from_bytes(&bytes(&group.private_seed)).expect("seed parse");
        let (sk, vk) = seed.expand();
        assert_eq!(
            &vk.as_bytes()[..],
            &bytes(&group.public_key)[..],
            "keygen diverged from the vector"
        );

        for t in &group.tests {
            seen += 1;
            let label = format!("tc {} ({})", t.tc_id, t.comment);
            let msg = bytes(&t.msg);
            let ctx = bytes(&t.ctx);
            // Missing rnd means deterministic signing with zero randomness.
            let rnd: [u8; RND_LENGTH] = match &t.rnd {
                Some(r) => bytes(r).try_into().expect("rnd length"),
                None => [0u8; RND_LENGTH],
            };

            match sk.sign(&msg, &ctx, &rnd) {
                Ok(sig) if is_valid(&t.result) => {
                    assert_eq!(
                        &sig.as_bytes()[..],
                        &bytes(&t.sig)[..],
                        "{label}: signature bytes"
                    );
                    assert_eq!(
                        vk.verify(&msg, &ctx, &sig),
                        Ok(()),
                        "{label}: own signature"
                    );
                }
                Ok(_) => panic!("{label}: signing succeeded, vector expects {:?}", t.flags),
                Err(e) => {
                    assert!(!is_valid(&t.result), "{label}: signing failed with {e:?}");
                    assert_eq!(e, expected_error(&ctx), "{label}");
                }
            }
        }
    }
    assert_eq!(
        seen, file.number_of_tests,
        "vector count differs from the header"
    );
}
