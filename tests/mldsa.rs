// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Public-API tests, run identically against every enabled parameter set.
//!
//! The levels come out of one implementation (see `src/level.rs`), so they get one test
//! suite. Whatever is proven for ML-DSA-65 is proven for 44 and 87, under the same test
//! names, and no level can quietly end up with less coverage than the others.

// TODO: add the Wycheproof ML-DSA vectors (github.com/C2SP/wycheproof, testvectors_v1).
// Vendor the JSON files with their source commit noted in a comment, like PROVENANCE.md
// does for the submodule, and check that accept/reject matches each case's "result"
// field, per level. Start with the verify files (mldsa_{44,65,87}_verify_test.json):
// their bad signatures hit our length checks and the C's canonicality checks, where a
// bug would matter for consensus. The sign vectors are also worth running through this
// wrapper: they cover our Rust-side prefix building (0x00 || ctxlen || ctx), which
// upstream's own Wycheproof runs never touch. The `wycheproof` crate has no ML-DSA
// support, so parse the JSON directly.

/// Defines the full suite for one parameter set.
///
/// The layout arguments describe the FIPS 204 signature encoding, which is
/// `c~ || z || hints`. The hint region is `omega` index slots followed by `k` per-row
/// running counts. `layout_is_current` checks those numbers still add up to the signature
/// length, so an upstream re-pin that changes the encoding is caught here rather than in
/// whatever fails next.
macro_rules! level_tests {
    (
        module = $module:ident,
        api = $api:path,
        ctilde = $ctilde:expr,
        z = $z:expr,
        omega = $omega:expr,
        k = $k:expr,
        pk_prefix = $pk_prefix:expr,
        pk_suffix = $pk_suffix:expr,
        kats = $kats:expr,
        kat_hashes = $kat_hashes:expr,
    ) => {
        mod $module {
            use mysten_mldsa_native_rs::{Error, MAX_CONTEXT_LENGTH, RND_LENGTH, SEED_LENGTH};
            use sha2::Digest as _;
            use $api::{
                Signature, SigningKey, SigningKeySeed, VerifyingKey, PUBLIC_KEY_LENGTH,
                SIGNATURE_LENGTH,
            };

            const CTILDE_BYTES: usize = $ctilde;
            const Z_BYTES: usize = $z;
            const OMEGA: usize = $omega;
            const K: usize = $k;
            const HINT_OFFSET: usize = CTILDE_BYTES + Z_BYTES;

            // Public key fragments for the all-0x07 seed, generated with aws-lc-rs. FIPS 204
            // fixes how a seed expands into a key, so there is exactly one right answer
            // here. If this fails, one of the two implementations is wrong.
            const SEED_07_PK_PREFIX: [u8; 16] = $pk_prefix;
            const SEED_07_PK_SUFFIX: [u8; 4] = $pk_suffix;

            /// Expected `(pk_head, pk_tail, sig_head, sig_tail)` for the three
            /// `KAT_INPUTS` cases below, produced by `@noble/post-quantum`, an independent
            /// implementation that shares no code with the vendored C.
            ///
            /// Pinning the signature bytes matters more than it looks. A test that only
            /// verifies its own output will happily pass while the wire format changes
            /// underneath it, whether from a backend swap (portable C, NEON, AVX2) or an
            /// upstream re-pin. For a scheme the network reaches consensus on, that silent
            /// change is a chain split.
            const KATS: [([u8; 8], [u8; 4], [u8; 8], [u8; 4]); 3] = $kats;

            /// SHA-256 of the full `(pk, sig)` for the same three cases. The fragments
            /// above keep a mismatch readable in test output; these cover every byte in
            /// between, so after a submodule re-pin, `cargo test` alone proves the
            /// outputs did not change.
            const KAT_HASHES: [(&str, &str); 3] = $kat_hashes;

            /// `(seed, msg_byte, msg_len, ctx_byte, ctx_len, rnd)`, the same for every level
            /// so all three are pinned under identical conditions. The cases cover what
            /// implementations actually disagree about: an empty message against a
            /// digest-sized one, an empty context against the 255-byte maximum, and the
            /// deterministic all-zero `rnd` against a patterned one.
            const KAT_INPUTS: [(u8, u8, usize, u8, usize, u8); 3] = [
                (0x01, 0x00, 0, 0x00, 0, 0x00),
                (0x02, 0xab, 32, 0x00, 0, 0x42),
                (0x05, 0xab, 32, 0x77, MAX_CONTEXT_LENGTH, 0x99),
            ];

            fn expand(byte: u8) -> (SigningKey, VerifyingKey) {
                SigningKeySeed::from([byte; SEED_LENGTH]).expand()
            }

            fn layout_is_current() {
                assert_eq!(
                    HINT_OFFSET + OMEGA + K,
                    SIGNATURE_LENGTH,
                    "signature layout constants no longer match the vendored C"
                );
            }

            #[test]
            fn keygen_is_deterministic_and_matches_reference() {
                let seed = SigningKeySeed::from([7u8; SEED_LENGTH]);
                assert_eq!(seed.as_bytes(), &[7u8; SEED_LENGTH]);
                let (_, vk_a) = seed.expand();
                let (_, vk_b) = seed.expand();
                assert_eq!(vk_a, vk_b);

                assert_eq!(vk_a.as_bytes()[..16], SEED_07_PK_PREFIX);
                assert_eq!(vk_a.as_bytes()[PUBLIC_KEY_LENGTH - 4..], SEED_07_PK_SUFFIX);
            }

            #[test]
            fn matches_cross_implementation_known_answers() {
                layout_is_current();
                for (i, ((seed, msg_byte, msg_len, ctx_byte, ctx_len, rnd), expected)) in
                    KAT_INPUTS.iter().zip(KATS.iter()).enumerate()
                {
                    let (pk_head, pk_tail, sig_head, sig_tail) = expected;
                    let msg = vec![*msg_byte; *msg_len];
                    let ctx = vec![*ctx_byte; *ctx_len];
                    let (sk, vk) = SigningKeySeed::from([*seed; SEED_LENGTH]).expand();

                    let pk = vk.as_bytes();
                    assert_eq!(pk[..8], *pk_head, "KAT {i}: public key head");
                    assert_eq!(
                        pk[PUBLIC_KEY_LENGTH - 4..],
                        *pk_tail,
                        "KAT {i}: public key tail"
                    );

                    let sig = sk
                        .sign(&msg, &ctx, &[*rnd; RND_LENGTH])
                        .expect("context length is within the FIPS 204 limit");
                    let sig = sig.as_bytes();
                    assert_eq!(
                        sig[..8],
                        *sig_head,
                        "KAT {i}: signature head — the wire format changed"
                    );
                    assert_eq!(
                        sig[SIGNATURE_LENGTH - 4..],
                        *sig_tail,
                        "KAT {i}: signature tail — the wire format changed"
                    );
                    let (pk_sha256, sig_sha256) = KAT_HASHES[i];
                    assert_eq!(
                        hex::encode(sha2::Sha256::digest(pk)),
                        pk_sha256,
                        "KAT {i}: full public key diverged"
                    );
                    assert_eq!(
                        hex::encode(sha2::Sha256::digest(sig)),
                        sig_sha256,
                        "KAT {i}: full signature diverged"
                    );
                }
            }

            #[test]
            fn sign_verify_roundtrip() {
                let (sk, vk) = expand(1);
                let sig = sk.sign(b"Hello, world!", b"", &[9u8; RND_LENGTH]).unwrap();
                assert!(vk.verify(b"Hello, world!", b"", &sig).is_ok());

                let empty_sig = sk.sign(b"", b"", &[9u8; RND_LENGTH]).unwrap();
                assert!(vk.verify(b"", b"", &empty_sig).is_ok());
            }

            #[test]
            fn signing_is_deterministic_in_seed_message_and_rnd() {
                // Signing in FIPS 204 is a pure function of (key, message, ctx, rnd).
                // Same inputs, same signature; change the rnd and it changes.
                let (sk, vk) = expand(2);
                let s1 = sk.sign(b"msg", b"", &[3u8; RND_LENGTH]).unwrap();
                let s2 = sk.sign(b"msg", b"", &[3u8; RND_LENGTH]).unwrap();
                let s3 = sk.sign(b"msg", b"", &[4u8; RND_LENGTH]).unwrap();
                assert_eq!(s1, s2);
                assert_ne!(s1, s3);
                assert!(vk.verify(b"msg", b"", &s1).is_ok());
                assert!(vk.verify(b"msg", b"", &s3).is_ok());
            }

            #[test]
            fn context_binds_signatures() {
                // A signature is bound to the context string it was made with. It has to
                // verify under that context and no other, including the empty one.
                let (sk, vk) = expand(3);
                let sig = sk.sign(b"msg", b"ctx-a", &[9u8; RND_LENGTH]).unwrap();
                assert!(vk.verify(b"msg", b"ctx-a", &sig).is_ok());
                assert_eq!(
                    vk.verify(b"msg", b"ctx-b", &sig),
                    Err(Error::InvalidSignature)
                );
                assert_eq!(vk.verify(b"msg", b"", &sig), Err(Error::InvalidSignature));

                let empty_ctx_sig = sk.sign(b"msg", b"", &[9u8; RND_LENGTH]).unwrap();
                assert_eq!(
                    vk.verify(b"msg", b"ctx-a", &empty_ctx_sig),
                    Err(Error::InvalidSignature)
                );
            }

            #[test]
            fn context_length_is_enforced_on_both_paths() {
                let (sk, vk) = expand(4);
                let max_ctx = [0x41u8; MAX_CONTEXT_LENGTH];
                let sig = sk.sign(b"msg", &max_ctx, &[9u8; RND_LENGTH]).unwrap();
                assert!(vk.verify(b"msg", &max_ctx, &sig).is_ok());

                let too_long = [0x41u8; MAX_CONTEXT_LENGTH + 1];
                assert_eq!(
                    sk.sign(b"msg", &too_long, &[9u8; RND_LENGTH]).unwrap_err(),
                    Error::ContextTooLong
                );
                assert_eq!(
                    vk.verify(b"msg", &too_long, &sig),
                    Err(Error::ContextTooLong)
                );
            }

            #[test]
            fn verify_rejects_wrong_message_and_wrong_key() {
                let (sk, vk) = expand(5);
                let (_, other_vk) = expand(6);
                let sig = sk.sign(b"Hello, world!", b"", &[9u8; RND_LENGTH]).unwrap();

                assert_eq!(
                    vk.verify(b"Hello, world?", b"", &sig),
                    Err(Error::InvalidSignature)
                );
                assert_eq!(
                    other_vk.verify(b"Hello, world!", b"", &sig),
                    Err(Error::InvalidSignature)
                );
            }

            #[test]
            fn verify_rejects_bit_flips_in_every_signature_region() {
                layout_is_current();
                let (sk, vk) = expand(8);
                let sig = sk.sign(b"msg", b"", &[9u8; RND_LENGTH]).unwrap();

                for index in [0, CTILDE_BYTES + Z_BYTES / 2, SIGNATURE_LENGTH - 1] {
                    let mut bytes = *sig.as_bytes();
                    bytes[index] ^= 1;
                    let tampered = Signature::from_bytes(&bytes).unwrap();
                    assert_eq!(
                        vk.verify(b"msg", b"", &tampered),
                        Err(Error::InvalidSignature),
                        "flip at byte {index} was not rejected"
                    );
                }
            }

            #[test]
            fn verify_rejects_non_canonical_hint_padding() {
                layout_is_current();
                let (sk, vk) = expand(10);
                let sig = sk.sign(b"msg", b"", &[9u8; RND_LENGTH]).unwrap();

                // The last signature byte holds the total hint count, and the index slots
                // past it are zero padding the decoder never looks at. Writing into that
                // padding gives a second byte encoding of the very same mathematical
                // signature. The C has to refuse it, because a valid ML-DSA signature has
                // exactly one encoding and anything else is malleability.
                let total_hints = sig.as_bytes()[SIGNATURE_LENGTH - 1] as usize;
                assert!(
                    total_hints < OMEGA,
                    "no padding slot free in this signature"
                );
                let mut bytes = *sig.as_bytes();
                assert_eq!(bytes[HINT_OFFSET + total_hints], 0);
                bytes[HINT_OFFSET + total_hints] = 1;
                let padded = Signature::from_bytes(&bytes).unwrap();
                assert_eq!(
                    vk.verify(b"msg", b"", &padded),
                    Err(Error::InvalidSignature)
                );
            }

            #[test]
            fn strict_lengths_seed() {
                let bytes = [11u8; SEED_LENGTH];
                assert!(SigningKeySeed::from_bytes(&bytes).is_ok());
                for wrong in [&bytes[..0], &bytes[..SEED_LENGTH - 1]] {
                    assert_eq!(
                        SigningKeySeed::from_bytes(wrong).unwrap_err(),
                        Error::InvalidLength
                    );
                }
                assert_eq!(
                    SigningKeySeed::from_bytes(&[bytes.to_vec(), vec![0u8]].concat()).unwrap_err(),
                    Error::InvalidLength
                );
            }

            #[test]
            fn strict_lengths_public_key() {
                let bytes = expand(11).1.as_bytes().to_vec();
                assert!(VerifyingKey::from_bytes(&bytes).is_ok());
                for wrong in [&bytes[..0], &bytes[..PUBLIC_KEY_LENGTH - 1]] {
                    assert_eq!(VerifyingKey::from_bytes(wrong), Err(Error::InvalidLength));
                }
                assert_eq!(
                    VerifyingKey::from_bytes(&[bytes, vec![0u8]].concat()),
                    Err(Error::InvalidLength)
                );
            }

            #[test]
            fn strict_lengths_signature() {
                let (sk, _) = expand(12);
                let bytes = sk
                    .sign(b"msg", b"", &[9u8; RND_LENGTH])
                    .unwrap()
                    .as_bytes()
                    .to_vec();
                assert!(Signature::from_bytes(&bytes).is_ok());
                for wrong in [&bytes[..0], &bytes[..SIGNATURE_LENGTH - 1]] {
                    assert_eq!(Signature::from_bytes(wrong), Err(Error::InvalidLength));
                }
                assert_eq!(
                    Signature::from_bytes(&[bytes, vec![0u8]].concat()),
                    Err(Error::InvalidLength)
                );
            }

            #[test]
            fn debug_output_is_redacted() {
                let seed = SigningKeySeed::from([0xAB; SEED_LENGTH]);
                assert_eq!(format!("{seed:?}"), "SigningKeySeed(<redacted>)");
                let (sk, vk) = seed.expand();
                assert_eq!(format!("{sk:?}"), "SigningKey(<redacted>)");
                // Public types are allowed to print a short prefix. Anything holding
                // secret key material must not print it at all, however it is formatted.
                assert!(!format!("{:?}", vk).contains("abab"));
            }

            #[test]
            fn seed_is_zeroized_on_drop() {
                // Checking that a destructor wiped something is awkward: normally the
                // storage is gone by the time you could look. ManuallyDrop keeps it alive
                // while drop_in_place runs the destructor, so reading the bytes afterwards
                // is defined behavior, and AddressSanitizer stays quiet. Reading a dead
                // stack slot after scope exit would be neither.
                let mut seed =
                    std::mem::ManuallyDrop::new(SigningKeySeed::from([13u8; SEED_LENGTH]));
                let ptr = seed.as_bytes().as_ptr();
                assert_eq!(seed.as_bytes(), &[13u8; SEED_LENGTH]);

                unsafe {
                    std::ptr::drop_in_place(&mut *seed as *mut SigningKeySeed);
                }

                // The expanded SigningKey wipes its own buffer on drop too, but that
                // buffer is boxed and handed back to the allocator, so there is nothing
                // left to look at. Only the inline seed can be observed this way.
                unsafe {
                    for i in 0..SEED_LENGTH {
                        assert_eq!(*ptr.add(i), 0, "seed byte {i} not zeroized");
                    }
                }
            }
        }
    };
}

level_tests!(
    module = mldsa65,
    api = mysten_mldsa_native_rs::mldsa65,
    ctilde = 48,
    z = 5 * 640,
    omega = 55,
    k = 6,
    pk_prefix = [
        0x37, 0x58, 0x4a, 0x6e, 0x42, 0x79, 0xae, 0xce, 0xe1, 0x30, 0xee, 0xa8, 0x90, 0x90, 0x45,
        0x36,
    ],
    pk_suffix = [0x62, 0x57, 0xd4, 0xc4],
    kats = [
        (
            [0xc4, 0xe9, 0x99, 0xa2, 0x03, 0x3f, 0xb0, 0xe1],
            [0xf8, 0x84, 0x59, 0xcf],
            [0x64, 0xf7, 0xe9, 0x06, 0x5e, 0x19, 0xad, 0x1e],
            [0x1a, 0x21, 0x27, 0x35],
        ),
        (
            [0x0a, 0x41, 0xf2, 0x50, 0x0f, 0x7e, 0x59, 0x63],
            [0x9e, 0x15, 0x41, 0xc7],
            [0x0e, 0xe3, 0x72, 0x0d, 0x10, 0x85, 0x86, 0x8d],
            [0x15, 0x1c, 0x20, 0x24],
        ),
        (
            [0xbd, 0x1e, 0x29, 0x87, 0x2b, 0xbf, 0x68, 0x3a],
            [0xb0, 0x4b, 0x29, 0x4f],
            [0xf7, 0xc7, 0x5d, 0x79, 0xe1, 0x3a, 0x52, 0x65],
            [0x0e, 0x13, 0x17, 0x1b],
        ),
    ],
    kat_hashes = [
        (
            "83ee80fcbcaf4872ed023e55cb10d7a2b4f1336a182115ea9c000f7449a7a9b0",
            "fc3b57f04d4702bca59c145179b052fcbf47c1985bdc6079887721a800239b3e",
        ),
        (
            "fda6ad37a2ab2ae563455cc73b3d263e13fc889914d975127dfbb3a07f274a1d",
            "451654a6e990370fb0f5922c179eb08621abb31290f788449d95a4f625a5375a",
        ),
        (
            "db0229df233110413da2c2031249e0a28300b68245b20668e723d11c127acb51",
            "29e7403be757a7fea1760db9117cf06c52b7a169000772539ff0ce2eda31cc3a",
        ),
    ],
);

#[cfg(feature = "mldsa44")]
level_tests!(
    module = mldsa44,
    api = mysten_mldsa_native_rs::mldsa44,
    ctilde = 32,
    z = 4 * 576,
    omega = 80,
    k = 4,
    pk_prefix = [
        0x22, 0x4c, 0x61, 0x92, 0x20, 0x72, 0x0e, 0x1a, 0x17, 0x05, 0x40, 0xab, 0x01, 0xa7, 0x70,
        0xa4,
    ],
    pk_suffix = [0x24, 0x32, 0xc6, 0xf6],
    kats = [
        (
            [0x5e, 0xce, 0x0a, 0x3d, 0x6c, 0x14, 0xba, 0xd1],
            [0x63, 0x58, 0x2a, 0x8a],
            [0x2e, 0x24, 0x3b, 0x3d, 0x46, 0x10, 0x3f, 0x83],
            [0x16, 0x2b, 0x38, 0x48],
        ),
        (
            [0xc9, 0x5b, 0x0e, 0x20, 0x06, 0x4e, 0x7d, 0xae],
            [0x11, 0x97, 0x49, 0x85],
            [0x7c, 0x9b, 0x77, 0x07, 0x5a, 0x5a, 0x84, 0x16],
            [0x17, 0x22, 0x33, 0x44],
        ),
        (
            [0xc4, 0x3b, 0xca, 0x61, 0x6b, 0x54, 0x2c, 0x74],
            [0xfe, 0x93, 0xae, 0x18],
            [0x21, 0x93, 0xfc, 0x81, 0x46, 0x26, 0x50, 0x12],
            [0x0a, 0x13, 0x1c, 0x27],
        ),
    ],
    kat_hashes = [
        (
            "bc7f72c940225e3998067ebef1d7cd2cad938de8f70b34c515a81d9efacac204",
            "607f5ce8db0430ab6c6e39769cd2c81c67011313bcd7eceb0d4342092bde5ba6",
        ),
        (
            "6e66c2c3c57116351798517f8d7c8d86c6ab57e12236799f00b869ae043a2da3",
            "35dd2bf272b000aa5d6364c920947b72e9c01a38bd8b09671345e24f042df9c1",
        ),
        (
            "4e4e2671157fa6d6c734bc952fde72c13ae6aa132a9b01eb215c17b6fd65567a",
            "d0cdf388a660fca25351649d2c22ac196b69533f4df7a9cf0ac3828e8154aeb3",
        ),
    ],
);

#[cfg(feature = "mldsa87")]
level_tests!(
    module = mldsa87,
    api = mysten_mldsa_native_rs::mldsa87,
    ctilde = 64,
    z = 7 * 640,
    omega = 75,
    k = 8,
    pk_prefix = [
        0x93, 0x9b, 0x14, 0xc0, 0x19, 0x43, 0xc7, 0x6c, 0x8d, 0x9c, 0xa7, 0x13, 0x99, 0xa3, 0x6f,
        0xc2,
    ],
    pk_suffix = [0x1f, 0xa1, 0xc0, 0x10],
    kats = [
        (
            [0x9e, 0x29, 0xea, 0x92, 0xb9, 0x29, 0x1b, 0xe1],
            [0x55, 0x49, 0x8c, 0x39],
            [0x52, 0xa9, 0x10, 0xe0, 0xd3, 0x3e, 0x06, 0xa2],
            [0x27, 0x2b, 0x31, 0x37],
        ),
        (
            [0xca, 0xc6, 0xae, 0x4c, 0xf2, 0xe8, 0x45, 0xb8],
            [0x02, 0x6d, 0xe9, 0x29],
            [0x38, 0x5b, 0x34, 0x6d, 0xe6, 0x52, 0x4a, 0x6d],
            [0x1e, 0x26, 0x2c, 0x36],
        ),
        (
            [0x5d, 0xf9, 0x1f, 0x10, 0xaf, 0xd5, 0x56, 0xb7],
            [0xdd, 0xa3, 0x79, 0xaf],
            [0x19, 0x47, 0xaa, 0xe3, 0x30, 0x22, 0x62, 0x51],
            [0x20, 0x2a, 0x34, 0x3f],
        ),
    ],
    kat_hashes = [
        (
            "ce2acc0495fd8ba20b7cafb87baba23e0c4285988a7c11a0b32defd26d7d35b1",
            "a02a18ae4b07a10e2d28987f2bc60ab4ed063001e8e2f0832c0c6a04165d85a7",
        ),
        (
            "2f76b55d0c6c14d3d659b8097f7d9329807f8e6f6d89415b1f4d39c82eb6c51d",
            "d3f7dc2e7445fcbceaf9b6fd32f697ab34cbea56c6d651c288f90b7ead8ac0da",
        ),
        (
            "fe41be59383db6db20c8c4ef08ca0ef54a94735f9def3b900a1a78dca8d03780",
            "d6d2909c3f4c8e6e24590b19c2895a3196fb140ea7edbb762e2fa52be8e12713",
        ),
    ],
);

/// The crate root re-exports ML-DSA-65, so root-imported types and `mldsa65::` types are
/// the same types; this pins that so the re-export cannot silently change level.
#[test]
fn root_reexport_is_mldsa65() {
    use mysten_mldsa_native_rs::{
        SigningKeySeed, PUBLIC_KEY_LENGTH, SEED_LENGTH, SIGNATURE_LENGTH,
    };

    assert_eq!(
        PUBLIC_KEY_LENGTH,
        mysten_mldsa_native_rs::mldsa65::PUBLIC_KEY_LENGTH
    );
    assert_eq!(
        SIGNATURE_LENGTH,
        mysten_mldsa_native_rs::mldsa65::SIGNATURE_LENGTH
    );

    let (_, vk_root) = SigningKeySeed::from([7u8; SEED_LENGTH]).expand();
    let (_, vk_level) =
        mysten_mldsa_native_rs::mldsa65::SigningKeySeed::from([7u8; SEED_LENGTH]).expand();
    assert_eq!(vk_root, vk_level);
}
