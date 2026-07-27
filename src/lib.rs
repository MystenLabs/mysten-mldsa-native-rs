// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    missing_docs,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

//! Minimal safe Rust wrapper around [mldsa-native]'s ML-DSA-65 (FIPS 204) implementation.
//!
//! The C library (a CBMC-verified C90 implementation maintained by the Post-Quantum
//! Cryptography Alliance, and the code AWS-LC and liboqs import) is vendored as a git
//! submodule and compiled by `build.rs`; see `PROVENANCE.md` for the exact pin. This crate
//! deliberately exposes a small, opinionated surface:
//!
//! - **The private key is the 32-byte FIPS 204 seed `/Xi`.** [`SigningKey`] retains the seed
//!   and exposes it via [`SigningKey::seed`]; the 4032-byte expanded signing key is an
//!   internal cache derived once at construction and is never exported. Key expansion is
//!   fully specified by FIPS 204 Algorithm 6, so the same seed yields the same key pair in
//!   every conforming implementation.
//! - **All randomness enters as explicit arguments.** [`SigningKey::sign`] takes the 32
//!   bytes of hedging randomness from the caller, and the C is compiled with its
//!   self-randomizing entry points removed, so no code path exists in which the library
//!   sources entropy. The optional `rand` feature adds OS-randomness conveniences on top.
//! - **The FIPS 204 context string is fixed to empty.** Context-string support can be added
//!   later as new methods without breaking this API.
//! - **Strict fixed-length parsing.** [`VerifyingKey::from_bytes`] and
//!   [`Signature::from_bytes`] accept exactly [`PUBLIC_KEY_LENGTH`] and
//!   [`SIGNATURE_LENGTH`] bytes.
//! - Secret material (seed and expanded key) is zeroized on drop, and [`SigningKey`]'s
//!   `Debug` output is redacted.
//!
//! ```rust
//! use mysten_mldsa_native_rs::{SigningKey, RND_LENGTH, SEED_LENGTH};
//!
//! const MSG: &str = "00010203";
//! const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";
//!
//! let seed: [u8; SEED_LENGTH] = hex::decode(SEED).unwrap().try_into().unwrap();
//! let msg = hex::decode(MSG).unwrap();
//!
//! let sk = SigningKey::from_seed(&seed);
//! let rnd = [42u8; RND_LENGTH]; // draw fresh from the OS per signature in real use
//! let sig = sk.sign(&msg, &rnd);
//! assert!(sk.verifying_key().verify(&msg, &sig).is_ok());
//! ```
//!
//! [mldsa-native]: https://github.com/pq-code-package/mldsa-native

use std::fmt;
use zeroize::Zeroize;
mod sys;

/// The length of a signing-key seed in bytes: the FIPS 204 seed `/Xi`
pub const SEED_LENGTH: usize = sys::MLDSA_SEEDBYTES;

/// The length of the hedged-signing randomness in bytes.
pub const RND_LENGTH: usize = sys::MLDSA_RNDBYTES;

/// The length of a public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = sys::MLDSA65_PUBLICKEYBYTES;

/// The length of a signature in bytes.
pub const SIGNATURE_LENGTH: usize = sys::MLDSA65_BYTES;

/// FIPS 204's pure-ML-DSA message prefix for the empty context: the domain separator 0x00
/// followed by the context length 0. The context is fixed to empty in this crate; a
/// different prefix would produce signatures incompatible with every verifier built from
/// this crate, so it is deliberately not exposed as a parameter.
const EMPTY_CONTEXT_PREFIX: [u8; 2] = [0x00, 0x00];

/// The error type of this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid parameter length
    InvalidLength,
    /// Invalid signature
    InvalidSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength => write!(f, "input has an invalid length"),
            Error::InvalidSignature => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for Error {}

/// An ML-DSA-65 signing key.
///
/// Constructed from, serialized as, and equal to its 32-byte FIPS 204 seed; the expanded
/// signing key and the encoded public key are caches computed once at construction so that
/// signing and public-key derivation never re-run key generation (~150 microseconds). All three
/// fields are zeroized on drop.
pub struct SigningKey {
    seed: [u8; SEED_LENGTH],
    expanded: Box<[u8]>,
    public: Box<[u8]>,
}

impl SigningKey {
    /// Expand `seed` into a signing key via ML-DSA.KeyGen_internal (FIPS 204 Algorithm 6).
    pub fn from_seed(seed: &[u8; SEED_LENGTH]) -> Self {
        let mut public = vec![0u8; PUBLIC_KEY_LENGTH].into_boxed_slice();
        let mut expanded = vec![0u8; sys::MLDSA65_SECRETKEYBYTES].into_boxed_slice();
        let rc = unsafe {
            sys::mldsa65_keypair_internal(public.as_mut_ptr(), expanded.as_mut_ptr(), seed.as_ptr())
        };
        assert_eq!(rc, 0, "ML-DSA-65 key expansion failed");
        SigningKey {
            seed: *seed,
            expanded,
            public,
        }
    }

    /// Generate a signing key from a fresh 32-byte seed drawn from the operating system.
    #[cfg(feature = "rand")]
    pub fn generate() -> Self {
        let mut seed = [0u8; SEED_LENGTH];
        getrandom::fill(&mut seed).expect("OS entropy source failed");
        let key = Self::from_seed(&seed);
        seed.zeroize();
        key
    }

    /// The 32-byte FIPS 204 seed `/Xi` this key was expanded from
    pub fn seed(&self) -> &[u8; SEED_LENGTH] {
        &self.seed
    }

    /// The public key derived from this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(
            self.public
                .as_ref()
                .try_into()
                .expect("cache has the fixed public key length"),
        )
    }

    /// Sign `message` with the caller-supplied hedging randomness `rnd` (FIPS 204
    /// Algorithm 2 with the context fixed to empty).
    ///
    /// `rnd` must be fresh randomness for every signature to get the hedged variant's
    /// resistance to fault attacks and randomness reuse; all-zero `rnd` yields FIPS 204's
    /// deterministic variant. `rnd` does not need to be kept secret, so it is not zeroized.
    pub fn sign(&self, message: &[u8], rnd: &[u8; RND_LENGTH]) -> Signature {
        let mut sig = [0u8; SIGNATURE_LENGTH];
        let rc = unsafe {
            sys::mldsa65_signature_internal(
                sig.as_mut_ptr(),
                message.as_ptr(),
                message.len(),
                EMPTY_CONTEXT_PREFIX.as_ptr(),
                EMPTY_CONTEXT_PREFIX.len(),
                rnd.as_ptr(),
                self.expanded.as_ptr(),
                0,
            )
        };
        assert_eq!(rc, 0, "ML-DSA-65 signing failed");
        Signature(sig)
    }

    /// Sign `message` with fresh hedging randomness drawn from the operating system.
    #[cfg(feature = "rand")]
    pub fn sign_randomized(&self, message: &[u8]) -> Signature {
        let mut rnd = [0u8; RND_LENGTH];
        getrandom::fill(&mut rnd).expect("OS entropy source failed");
        self.sign(message, &rnd)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.expanded.zeroize();
        self.public.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for SigningKey {}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        self.seed == other.seed
    }
}

impl Eq for SigningKey {}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey(<redacted>)")
    }
}

/// An ML-DSA-65 public key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VerifyingKey([u8; PUBLIC_KEY_LENGTH]);

impl VerifyingKey {
    /// Parse a public key from exactly [`PUBLIC_KEY_LENGTH`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .try_into()
            .map(VerifyingKey)
            .map_err(|_| Error::InvalidLength)
    }

    /// The encoded public key bytes.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.0
    }

    /// Verify `signature` over `message` under this key (FIPS 204 Algorithm 3, context fixed to empty).
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        // NULL/0 is upstream's documented encoding of the (fixed empty) context.
        let rc = unsafe {
            sys::mldsa65_verify(
                signature.0.as_ptr(),
                message.as_ptr(),
                message.len(),
                std::ptr::null(),
                0,
                self.0.as_ptr(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl AsRef<[u8]> for VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// A derived Debug would dump 1952 bytes; a short prefix identifies the key in test output.
impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey(")?;
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…)")
    }
}

/// An ML-DSA-65 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LENGTH]);

impl Signature {
    /// Parse a signature from exactly [`SIGNATURE_LENGTH`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .try_into()
            .map(Signature)
            .map_err(|_| Error::InvalidLength)
    }

    /// The encoded signature bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature(")?;
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…)")
    }
}
