// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use mysten_mldsa_native_rs::{
    Error, Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, RND_LENGTH, SEED_LENGTH,
    SIGNATURE_LENGTH,
};

// ML-DSA-65 signature layout (FIPS 204 / mldsa-native params.h)
const CTILDE_BYTES: usize = 48;
const Z_BYTES: usize = 5 * 640;
const OMEGA: usize = 55;
const K: usize = 6;
const HINT_OFFSET: usize = CTILDE_BYTES + Z_BYTES;

// Expected public key fragments for the all-0x07 seed
const SEED_07_PK_PREFIX: [u8; 16] = [
    0x37, 0x58, 0x4a, 0x6e, 0x42, 0x79, 0xae, 0xce, 0xe1, 0x30, 0xee, 0xa8, 0x90, 0x90, 0x45, 0x36,
];
const SEED_07_PK_SUFFIX: [u8; 4] = [0x62, 0x57, 0xd4, 0xc4];

fn layout_is_current() {
    assert_eq!(
        HINT_OFFSET + OMEGA + K,
        SIGNATURE_LENGTH,
        "signature layout constants no longer match the vendored C"
    );
}

#[test]
fn keygen_is_deterministic_and_matches_reference() {
    let seed = [7u8; SEED_LENGTH];
    let a = SigningKey::from_seed(&seed);
    let b = SigningKey::from_seed(&seed);
    assert_eq!(a, b);
    assert_eq!(a.verifying_key(), b.verifying_key());
    assert_eq!(a.seed(), &seed);

    let pk = a.verifying_key();
    assert_eq!(pk.as_bytes()[..16], SEED_07_PK_PREFIX);
    assert_eq!(pk.as_bytes()[PUBLIC_KEY_LENGTH - 4..], SEED_07_PK_SUFFIX);
}

#[test]
fn sign_verify_roundtrip() {
    let sk = SigningKey::from_seed(&[1u8; SEED_LENGTH]);
    let sig = sk.sign(b"Hello, world!", &[9u8; RND_LENGTH]);
    assert!(sk.verifying_key().verify(b"Hello, world!", &sig).is_ok());

    let empty_sig = sk.sign(b"", &[9u8; RND_LENGTH]);
    assert!(sk.verifying_key().verify(b"", &empty_sig).is_ok());
}

#[test]
fn signing_is_deterministic_in_seed_message_and_rnd() {
    // FIPS 204 signing is a pure function of (key, message, rnd)
    let sk = SigningKey::from_seed(&[2u8; SEED_LENGTH]);
    let s1 = sk.sign(b"msg", &[3u8; RND_LENGTH]);
    let s2 = sk.sign(b"msg", &[3u8; RND_LENGTH]);
    let s3 = sk.sign(b"msg", &[4u8; RND_LENGTH]);
    assert_eq!(s1, s2);
    assert_ne!(s1, s3);
    assert!(sk.verifying_key().verify(b"msg", &s1).is_ok());
    assert!(sk.verifying_key().verify(b"msg", &s3).is_ok());
}

#[test]
fn verify_rejects_wrong_message_and_wrong_key() {
    let sk = SigningKey::from_seed(&[5u8; SEED_LENGTH]);
    let other = SigningKey::from_seed(&[6u8; SEED_LENGTH]);
    let sig = sk.sign(b"Hello, world!", &[9u8; RND_LENGTH]);

    assert_eq!(
        sk.verifying_key().verify(b"Hello, world?", &sig),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        other.verifying_key().verify(b"Hello, world!", &sig),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn verify_rejects_bit_flips_in_every_signature_region() {
    layout_is_current();
    let sk = SigningKey::from_seed(&[8u8; SEED_LENGTH]);
    let sig = sk.sign(b"msg", &[9u8; RND_LENGTH]);

    for index in [0, CTILDE_BYTES + Z_BYTES / 2, SIGNATURE_LENGTH - 1] {
        let mut bytes = *sig.as_bytes();
        bytes[index] ^= 1;
        let tampered = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(
            sk.verifying_key().verify(b"msg", &tampered),
            Err(Error::InvalidSignature),
            "flip at byte {index} was not rejected"
        );
    }
}

#[test]
fn verify_rejects_non_canonical_hint_padding() {
    layout_is_current();
    let sk = SigningKey::from_seed(&[10u8; SEED_LENGTH]);
    let sig = sk.sign(b"msg", &[9u8; RND_LENGTH]);

    // The last signature byte is the total hint count
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
        sk.verifying_key().verify(b"msg", &padded),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn strict_lengths_public_key() {
    let sk = SigningKey::from_seed(&[11u8; SEED_LENGTH]);
    let bytes = sk.verifying_key().as_bytes().to_vec();
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
    let sk = SigningKey::from_seed(&[12u8; SEED_LENGTH]);
    let bytes = sk.sign(b"msg", &[9u8; RND_LENGTH]).as_bytes().to_vec();
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
    let sk = SigningKey::from_seed(&[0xAB; SEED_LENGTH]);
    assert_eq!(format!("{sk:?}"), "SigningKey(<redacted>)");
    // The public types may print prefixes, but the signing key must never leak through
    // formatting; the seed is reachable only through the explicit accessor.
    assert!(!format!("{:?}", sk.verifying_key()).contains("abab"));
}

#[test]
fn seed_is_zeroized_on_drop() {
    let mut sk = std::mem::ManuallyDrop::new(SigningKey::from_seed(&[13u8; SEED_LENGTH]));
    let ptr = sk.seed().as_ptr();
    assert_eq!(sk.seed(), &[13u8; SEED_LENGTH]);

    unsafe {
        std::ptr::drop_in_place(&mut *sk as *mut SigningKey);
    }

    // Only the inline seed is observable after the drop
    unsafe {
        for i in 0..SEED_LENGTH {
            assert_eq!(*ptr.add(i), 0, "seed byte {i} not zeroized");
        }
    }
}

#[cfg(feature = "rand")]
#[test]
fn rand_feature_conveniences() {
    let sk = SigningKey::generate();
    let other = SigningKey::generate();
    assert_ne!(sk, other, "two generated keys collided");

    let s1 = sk.sign_randomized(b"msg");
    let s2 = sk.sign_randomized(b"msg");
    assert_ne!(s1, s2, "hedged signatures reused randomness");
    assert!(sk.verifying_key().verify(b"msg", &s1).is_ok());
    assert!(sk.verifying_key().verify(b"msg", &s2).is_ok());
}
