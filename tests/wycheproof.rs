// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Wycheproof ML-DSA vectors, from the `wycheproof` crate (0.7 added ML-DSA), run against
//! every enabled parameter set.

use mysten_mldsa_native_rs::Error;
use wycheproof::TestResult;

fn is_valid(result: TestResult) -> bool {
    match result {
        TestResult::Valid => true,
        TestResult::Invalid => false,
        TestResult::Acceptable => panic!("ML-DSA vectors have no acceptable cases"),
    }
}

// Every invalid case must fail for the reason the vector names, so a verifier that
// rejects for the wrong reason, or a parser that rejects what the verifier should, shows.
fn expected_error(invalid_context: bool) -> Error {
    if invalid_context {
        Error::ContextTooLong
    } else {
        Error::InvalidSignature
    }
}

/// Defines both Wycheproof tests for one parameter set. The counts pin the shape of the
/// vector files, so a crate update that adds or drops cases is noticed.
macro_rules! level_tests {
    (
        module = $module:ident,
        api = $api:path,
        verify_set = $verify_set:ident,
        verify_tests = $verify_tests:expr,
        sign_set = $sign_set:ident,
        sign_tests = $sign_tests:expr,
        mu_only_tests = $mu_only_tests:expr,
    ) => {
        mod $module {
            use super::{expected_error, is_valid};
            use mysten_mldsa_native_rs::{Error, RND_LENGTH};
            use wycheproof::mldsa_sign::{
                TestFlag as SignFlag, TestName as SignName, TestSet as SignSet,
            };
            use wycheproof::mldsa_verify::{
                TestFlag as VerifyFlag, TestName as VerifyName, TestSet as VerifySet,
            };
            use $api::{Signature, SigningKeySeed, VerifyingKey};

            #[test]
            fn wycheproof_verify() {
                let set = VerifySet::load(VerifyName::$verify_set).unwrap();
                assert_eq!(
                    set.number_of_tests, $verify_tests,
                    "vector set changed shape"
                );

                for group in &set.test_groups {
                    let vk = match VerifyingKey::from_bytes(&group.pubkey) {
                        Ok(vk) => vk,
                        Err(Error::InvalidLength) => {
                            for t in &group.tests {
                                assert!(
                                    !is_valid(t.result)
                                        && t.flags.contains(&VerifyFlag::IncorrectPublicKeyLength),
                                    "tc {}: key rejected but vector expects it parsed",
                                    t.tc_id
                                );
                            }
                            continue;
                        }
                        Err(e) => panic!("public key parse: {e:?}"),
                    };

                    for t in &group.tests {
                        let label = format!("tc {} ({})", t.tc_id, t.comment);
                        let ctx = t.ctx.as_ref().map_or(&[][..], |c| &c[..]);
                        let sig = match Signature::from_bytes(&t.sig) {
                            Ok(sig) => sig,
                            Err(Error::InvalidLength) => {
                                assert!(
                                    !is_valid(t.result)
                                        && t.flags.contains(&VerifyFlag::IncorrectSignatureLength),
                                    "{label}: signature rejected but vector expects it parsed"
                                );
                                continue;
                            }
                            Err(e) => panic!("{label}: signature parse: {e:?}"),
                        };

                        let got = vk.verify(&t.msg, ctx, &sig);
                        if is_valid(t.result) {
                            assert_eq!(got, Ok(()), "{label}: valid signature rejected");
                        } else {
                            let want =
                                expected_error(t.flags.contains(&VerifyFlag::InvalidContext));
                            assert_eq!(got, Err(want), "{label}: {:?}", t.flags);
                        }
                    }
                }
            }

            #[test]
            fn wycheproof_sign_seed() {
                let set = SignSet::load(SignName::$sign_set).unwrap();
                assert_eq!(set.number_of_tests, $sign_tests, "vector set changed shape");
                let mut mu_only = 0;

                for group in &set.test_groups {
                    let seed = group
                        .privseed
                        .as_ref()
                        .expect("seed vectors carry privateSeed");
                    let seed = match SigningKeySeed::from_bytes(seed) {
                        Ok(seed) => seed,
                        Err(Error::InvalidLength) => {
                            for t in &group.tests {
                                assert!(
                                    !is_valid(t.result)
                                        && t.flags.contains(&SignFlag::IncorrectPrivateKeyLength),
                                    "tc {}: seed rejected but vector expects it parsed",
                                    t.tc_id
                                );
                            }
                            continue;
                        }
                        Err(e) => panic!("seed parse: {e:?}"),
                    };
                    let (sk, vk) = seed.expand();
                    let pubkey = group
                        .pubkey
                        .as_ref()
                        .expect("seed groups carry the public key");
                    assert_eq!(
                        &vk.as_bytes()[..],
                        &pubkey[..],
                        "keygen diverged from the vector"
                    );

                    for t in &group.tests {
                        let label = format!("tc {} ({})", t.tc_id, t.comment);
                        // `Internal` cases give only a precomputed mu, which this crate does
                        // not sign over.
                        let Some(msg) = &t.msg else {
                            assert!(
                                t.flags.contains(&SignFlag::Internal),
                                "{label}: msg missing"
                            );
                            mu_only += 1;
                            continue;
                        };
                        let ctx = t.ctx.as_ref().map_or(&[][..], |c| &c[..]);
                        // Vectors without `rnd` are the deterministic variant: rnd = 0^32.
                        let rnd: [u8; RND_LENGTH] = match &t.rnd {
                            Some(r) => r[..].try_into().expect("rnd length"),
                            None => [0u8; RND_LENGTH],
                        };

                        match sk.sign(msg, ctx, &rnd) {
                            Ok(sig) if is_valid(t.result) => {
                                assert_eq!(
                                    &sig.as_bytes()[..],
                                    &t.sig[..],
                                    "{label}: signature bytes"
                                );
                                assert_eq!(
                                    vk.verify(msg, ctx, &sig),
                                    Ok(()),
                                    "{label}: own signature"
                                );
                            }
                            Ok(_) => {
                                panic!("{label}: signing succeeded, vector expects {:?}", t.flags)
                            }
                            Err(e) => {
                                assert!(!is_valid(t.result), "{label}: signing failed with {e:?}");
                                let want =
                                    expected_error(t.flags.contains(&SignFlag::InvalidContext));
                                assert_eq!(e, want, "{label}");
                            }
                        }
                    }
                }
                assert_eq!(mu_only, $mu_only_tests, "mu-only vector count changed");
            }
        }
    };
}

level_tests!(
    module = mldsa65,
    api = mysten_mldsa_native_rs::mldsa65,
    verify_set = MlDsa65Verify,
    verify_tests = 210,
    sign_set = MlDsa65SignSeed,
    sign_tests = 105,
    mu_only_tests = 17,
);

#[cfg(feature = "mldsa44")]
level_tests!(
    module = mldsa44,
    api = mysten_mldsa_native_rs::mldsa44,
    verify_set = MlDsa44Verify,
    verify_tests = 180,
    sign_set = MlDsa44SignSeed,
    sign_tests = 86,
    mu_only_tests = 8,
);

#[cfg(feature = "mldsa87")]
level_tests!(
    module = mldsa87,
    api = mysten_mldsa_native_rs::mldsa87,
    verify_set = MlDsa87Verify,
    verify_tests = 241,
    sign_set = MlDsa87SignSeed,
    sign_tests = 96,
    mu_only_tests = 17,
);
