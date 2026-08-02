// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    missing_docs,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

//! Minimal safe Rust wrapper around [mldsa-native]'s ML-DSA (FIPS 204) implementation.
//!
//! The C library (a CBMC-verified C90 implementation maintained by the Post-Quantum
//! Cryptography Alliance) is vendored as a git submodule and compiled by `build.rs`;
//! see `PROVENANCE.md` for the exact pin. This crate deliberately exposes a small, opinionated surface:
//!
//! - Two signing key forms. [`SigningKeySeed`] is the 32-byte FIPS 204 seed `/Xi`, the
//!   storage and wire form. [`SigningKeySeed::expand`] derives the operational
//!   [`SigningKey`] (where [`SigningKey::sign`] lives) together with the corresponding
//!   [`VerifyingKey`]. Key expansion is fully specified by FIPS 204 Algorithm 6, so the
//!   same seed yields the same key pair in every compliant implementation. Consumers pick
//!   the space-time trade-off: store seeds and expand on demand, or keep expanded keys
//!   around.
//! - No entropy source in the library. The C is compiled with `MLD_CONFIG_NO_RANDOMIZED_API`,
//!   so its self-randomizing entry points do not exist and
//!   no `randombytes` symbol is required or referenced at link time. All randomness enters
//!   as explicit arguments: the seed for key generation, `rnd` for hedged signing.
//! - The FIPS 204 context string is a parameter. `sign` and `verify` take `ctx`
//!   (at most [`MAX_CONTEXT_LENGTH`] bytes); consumers that need no domain separation pass
//!   the default empty string.
//! - Strict fixed-length parsing. `VerifyingKey::from_bytes` and `Signature::from_bytes`
//!   accept exactly `PUBLIC_KEY_LENGTH` and `SIGNATURE_LENGTH` bytes.
//! - Secret material is zeroized on drop, and the signing key types' `Debug` output is
//!   redacted. The expanded key is heap-allocated so the C writes it at its final address
//!   and moves of the key never copy secret bytes.
//!
//! ```rust
//! use mysten_mldsa_native_rs::{SigningKeySeed, RND_LENGTH, SEED_LENGTH};
//!
//! const MSG: &str = "00010203";
//! const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";
//!
//! let seed: [u8; SEED_LENGTH] = hex::decode(SEED).unwrap().try_into().unwrap();
//! let msg = hex::decode(MSG).unwrap();
//!
//! let (sk, vk) = SigningKeySeed::from(seed).expand();
//! let rnd = [42u8; RND_LENGTH]; // draw fresh from the OS per signature in real use
//! let sig = sk.sign(&msg, b"", &rnd).unwrap();
//! assert!(vk.verify(&msg, b"", &sig).is_ok());
//! ```
//!
//! # Parameter sets
//!
//! ML-DSA-65 is always available, and its types are re-exported at the crate root, so
//! plain [`SigningKeySeed`] and friends mean ML-DSA-65. The other two levels are opt-in
//! cargo features because each one compiles another copy of the C:
//!
//! | Level | Feature | Module | Public key | Signature |
//! |---|---|---|---|---|
//! | ML-DSA-44 | `mldsa44` | [`mldsa44`] | 1312 B | 2420 B |
//! | ML-DSA-65 | *(always on)* | [`mldsa65`] | 1952 B | 3309 B |
//! | ML-DSA-87 | `mldsa87` | [`mldsa87`] | 2592 B | 4627 B |
//!
//! Every level exposes the identical API, so switching is a change of import path:
//!
//! ```rust
//! # use mysten_mldsa_native_rs::{RND_LENGTH, SEED_LENGTH};
//! use mysten_mldsa_native_rs::mldsa65::SigningKeySeed; // or mldsa44::/mldsa87:: with the feature
//!
//! let (sk, vk) = SigningKeySeed::from([7u8; SEED_LENGTH]).expand();
//! let sig = sk.sign(b"message", b"", &[42u8; RND_LENGTH]).unwrap();
//! assert!(vk.verify(b"message", b"", &sig).is_ok());
//! ```
//!
//! Levels are not interchangeable on the wire: their keys and signatures have different
//! lengths and do not verify against each other. Picking one is a protocol decision, not a
//! runtime switch.
//!
//! [mldsa-native]: https://github.com/pq-code-package/mldsa-native

mod level;
mod sys;

/// ML-DSA-44 (FIPS 204). Requires the `mldsa44` feature.
#[cfg(feature = "mldsa44")]
pub mod mldsa44 {
    crate::level::define_level!(
        level = "44",
        pk_len = crate::sys::MLDSA44_PUBLICKEYBYTES,
        sk_len = crate::sys::MLDSA44_SECRETKEYBYTES,
        sig_len = crate::sys::MLDSA44_BYTES,
        keypair_internal = crate::sys::mldsa44_keypair_internal,
        signature_internal = crate::sys::mldsa44_signature_internal,
        verify = crate::sys::mldsa44_verify,
    );
}

/// ML-DSA-65 (FIPS 204), this crate's default level; its types are re-exported at the
/// crate root.
pub mod mldsa65 {
    crate::level::define_level!(
        level = "65",
        pk_len = crate::sys::MLDSA65_PUBLICKEYBYTES,
        sk_len = crate::sys::MLDSA65_SECRETKEYBYTES,
        sig_len = crate::sys::MLDSA65_BYTES,
        keypair_internal = crate::sys::mldsa65_keypair_internal,
        signature_internal = crate::sys::mldsa65_signature_internal,
        verify = crate::sys::mldsa65_verify,
    );
}

/// ML-DSA-87 (FIPS 204). Requires the `mldsa87` feature.
#[cfg(feature = "mldsa87")]
pub mod mldsa87 {
    crate::level::define_level!(
        level = "87",
        pk_len = crate::sys::MLDSA87_PUBLICKEYBYTES,
        sk_len = crate::sys::MLDSA87_SECRETKEYBYTES,
        sig_len = crate::sys::MLDSA87_BYTES,
        keypair_internal = crate::sys::mldsa87_keypair_internal,
        signature_internal = crate::sys::mldsa87_signature_internal,
        verify = crate::sys::mldsa87_verify,
    );
}

pub use mldsa65::*;

use core::fmt;

/// The length of a signing-key seed in bytes: the FIPS 204 seed `/Xi`. The same for every
/// parameter set.
pub const SEED_LENGTH: usize = sys::MLDSA_SEEDBYTES;

/// The length of the hedged-signing randomness in bytes. The same for every parameter set.
pub const RND_LENGTH: usize = sys::MLDSA_RNDBYTES;

/// The maximum length of the FIPS 204 context string in bytes.
pub const MAX_CONTEXT_LENGTH: usize = 255;

/// The error type of this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid parameter length
    InvalidLength,
    /// Invalid signature
    InvalidSignature,
    /// Context string longer than [`MAX_CONTEXT_LENGTH`] bytes
    ContextTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength => write!(f, "input has an invalid length"),
            Error::InvalidSignature => write!(f, "signature verification failed"),
            Error::ContextTooLong => write!(f, "context string exceeds 255 bytes"),
        }
    }
}

impl std::error::Error for Error {}

/// Build the FIPS 204 pure-ML-DSA message prefix `0x00 || ctxlen || ctx`. The C validates
/// the context length only on the verify path, so our signing path enforces it here.
fn domain_separation_prefix(ctx: &[u8]) -> Result<([u8; 2 + MAX_CONTEXT_LENGTH], usize), Error> {
    if ctx.len() > MAX_CONTEXT_LENGTH {
        return Err(Error::ContextTooLong);
    }
    let mut prefix = [0u8; 2 + MAX_CONTEXT_LENGTH];
    prefix[1] = ctx.len() as u8;
    prefix[2..2 + ctx.len()].copy_from_slice(ctx);
    Ok((prefix, 2 + ctx.len()))
}
