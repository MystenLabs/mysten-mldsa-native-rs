// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use mysten_mldsa_native_rs::{
    Error, Signature, SigningKey, SigningKeySeed, VerifyingKey, MAX_CONTEXT_LENGTH,
    PUBLIC_KEY_LENGTH, RND_LENGTH, SEED_LENGTH, SIGNATURE_LENGTH,
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

    let pk = vk_a;
    assert_eq!(pk.as_bytes()[..16], SEED_07_PK_PREFIX);
    assert_eq!(pk.as_bytes()[PUBLIC_KEY_LENGTH - 4..], SEED_07_PK_SUFFIX);
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
    // FIPS 204 signing is a pure function of (key, message, ctx, rnd)
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
    // A signature is bound to its context string: it must verify only under the exact ctx
    // it was produced with.
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
    // The public types may print prefixes, but signing key material must never leak through
    // formatting.
    assert!(!format!("{:?}", vk).contains("abab"));
}

#[test]
fn seed_is_zeroized_on_drop() {
    // ManuallyDrop keeps the storage alive while drop_in_place runs the destructor, so
    // observing the wiped bytes afterwards is defined behavior (and AddressSanitizer-clean,
    // unlike reading a dead stack slot after scope exit).
    let mut seed = std::mem::ManuallyDrop::new(SigningKeySeed::from([13u8; SEED_LENGTH]));
    let ptr = seed.as_bytes().as_ptr();
    assert_eq!(seed.as_bytes(), &[13u8; SEED_LENGTH]);

    unsafe {
        std::ptr::drop_in_place(&mut *seed as *mut SigningKeySeed);
    }

    // The expanded SigningKey's buffers are wiped by its own Drop, but they are boxed and
    // returned to the allocator with the free, so only the inline seed is observable.
    unsafe {
        for i in 0..SEED_LENGTH {
            assert_eq!(*ptr.add(i), 0, "seed byte {i} not zeroized");
        }
    }
}
