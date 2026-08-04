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
//! - Strict fixed-length parsing. [`VerifyingKey::from_bytes`] and
//!   [`Signature::from_bytes`] accept exactly [`PUBLIC_KEY_LENGTH`] and
//!   [`SIGNATURE_LENGTH`] bytes.
//! - Secret material is zeroized on drop, and the signing key types' `Debug` output is
//!   redacted. The expanded and public keys are heap-allocated so the C writes them at
//!   their final address and moves of the key never copy secret bytes.
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
//! [mldsa-native]: https://github.com/pq-code-package/mldsa-native

use std::fmt;
use zeroize::Zeroize;
// The runtime CPU probe the vendored C calls in native builds.
#[cfg(feature = "native")]
mod capability;
mod sys;

/// The length of a signing-key seed in bytes: the FIPS 204 seed `/Xi`
pub const SEED_LENGTH: usize = sys::MLDSA_SEEDBYTES;

/// The length of the hedged-signing randomness in bytes.
pub const RND_LENGTH: usize = sys::MLDSA_RNDBYTES;

/// The length of a public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = sys::MLDSA65_PUBLICKEYBYTES;

/// The length of a signature in bytes.
pub const SIGNATURE_LENGTH: usize = sys::MLDSA65_BYTES;

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

/// An ML-DSA-65 signing key seed: the 32-byte FIPS 204 seed `/Xi`, the storage and wire
/// form of a private key. Zeroized on drop.
#[derive(PartialEq, Eq)]
pub struct SigningKeySeed([u8; SEED_LENGTH]);

impl SigningKeySeed {
    /// Parse a seed from exactly [`SEED_LENGTH`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .try_into()
            .map(SigningKeySeed)
            .map_err(|_| Error::InvalidLength)
    }

    /// The seed bytes, the private key's one and only serialized form.
    pub fn as_bytes(&self) -> &[u8; SEED_LENGTH] {
        &self.0
    }

    /// Expand into the operational [`SigningKey`] and its [`VerifyingKey`] via
    /// ML-DSA.KeyGen_internal (FIPS 204 Algorithm 6). The public key is a byproduct of the
    /// same expansion, so both cost one keygen (tens of microseconds, backend-dependent);
    /// callers that sign repeatedly are recommended to keep the expanded key instead of
    /// reexpanding it.
    pub fn expand(&self) -> (SigningKey, VerifyingKey) {
        let mut public = [0u8; PUBLIC_KEY_LENGTH];
        let mut expanded = vec![0u8; sys::MLDSA65_SECRETKEYBYTES].into_boxed_slice();
        let rc = unsafe {
            sys::mldsa65_keypair_internal(
                public.as_mut_ptr(),
                expanded.as_mut_ptr(),
                self.0.as_ptr(),
            )
        };
        assert_eq!(rc, 0, "ML-DSA-65 key expansion failed");
        (SigningKey { expanded }, VerifyingKey(public))
    }
}

impl From<[u8; SEED_LENGTH]> for SigningKeySeed {
    fn from(seed: [u8; SEED_LENGTH]) -> Self {
        SigningKeySeed(seed)
    }
}

impl AsRef<[u8]> for SigningKeySeed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SigningKeySeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for SigningKeySeed {}

impl fmt::Debug for SigningKeySeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKeySeed(<redacted>)")
    }
}

/// An ML-DSA-65 operational signing key: the expanded signing key derived from a
/// [`SigningKeySeed`], which also yields the corresponding [`VerifyingKey`]. Does not
/// retain the seed or the public key and has no serialized form; serialize the seed
/// instead. Zeroized on drop.
///
/// The field is heap-allocated so the C writes it at its final address and moves of the
/// key never copy secret bytes onto the stack.
pub struct SigningKey {
    expanded: Box<[u8]>,
}

impl SigningKey {
    /// Sign `message` under the context string `ctx` with the caller-supplied hedging
    /// randomness `rnd` (FIPS 204 Algorithm 2).
    ///
    /// `rnd` must be fresh randomness for every signature to get the hedged variant's
    /// resistance to fault attacks and randomness reuse; all-zero `rnd` yields FIPS 204's
    /// deterministic variant. `rnd` does not need to be kept secret, so it is not zeroized.
    pub fn sign(
        &self,
        message: &[u8],
        ctx: &[u8],
        rnd: &[u8; RND_LENGTH],
    ) -> Result<Signature, Error> {
        let (prefix, prefix_len) = domain_separation_prefix(ctx)?;
        let mut sig = [0u8; SIGNATURE_LENGTH];
        let rc = unsafe {
            sys::mldsa65_signature_internal(
                sig.as_mut_ptr(),
                message.as_ptr(),
                message.len(),
                prefix.as_ptr(),
                prefix_len,
                rnd.as_ptr(),
                self.expanded.as_ptr(),
                0,
            )
        };
        assert_eq!(rc, 0, "ML-DSA-65 signing failed");
        Ok(Signature(sig))
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.expanded.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for SigningKey {}

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

    /// Verify `signature` over `message` under the context string `ctx` (FIPS 204 Algorithm 3).
    pub fn verify(&self, message: &[u8], ctx: &[u8], signature: &Signature) -> Result<(), Error> {
        if ctx.len() > MAX_CONTEXT_LENGTH {
            return Err(Error::ContextTooLong);
        }
        let rc = unsafe {
            sys::mldsa65_verify(
                signature.0.as_ptr(),
                message.as_ptr(),
                message.len(),
                ctx.as_ptr(),
                ctx.len(),
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
