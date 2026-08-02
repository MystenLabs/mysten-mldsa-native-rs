// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The API for one parameter set, written once and instantiated per level.
//!
//! Why a macro?
//! ML-DSA-44, 65 and 87 have exactly the same API. All that changes between them is a
//! handful of byte lengths and which C functions get called:
//!
//!     one macro       -> a fix or an audit finding lands on all three levels at once
//!     three copies    -> the levels drift apart, and nobody notices which one is stale
//!
//! So the types live here and each level instantiates them. What comes out is an ordinary
//! module of concrete types. There are no generics and no trait objects, so callers see the
//! same API they would have written by hand.

/// Defines a parameter set's full API in the current module.
///
/// `$sk_len` is the expanded signing key length. It never appears in the public API; it is
/// here only to size the buffer the C writes into.
macro_rules! define_level {
    (
        level = $level:literal,
        pk_len = $pk_len:expr,
        sk_len = $sk_len:expr,
        sig_len = $sig_len:expr,
        keypair_internal = $keypair:path,
        signature_internal = $signature:path,
        verify = $verify:path,
    ) => {
        use core::fmt;
        use zeroize::Zeroize;

        use crate::{domain_separation_prefix, Error, RND_LENGTH, SEED_LENGTH};

        /// The length of a public key in bytes.
        pub const PUBLIC_KEY_LENGTH: usize = $pk_len;

        /// The length of a signature in bytes.
        pub const SIGNATURE_LENGTH: usize = $sig_len;

        #[doc = concat!("An ML-DSA-", $level, " signing key seed: the 32-byte FIPS 204 seed")]
        /// `/Xi`, the storage and wire form of a private key. Zeroized on drop.
        #[derive(PartialEq, Eq)]
        pub struct SigningKeySeed([u8; SEED_LENGTH]);

        impl SigningKeySeed {
            /// Parse a seed from exactly [`SEED_LENGTH`](crate::SEED_LENGTH) bytes.
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

            /// Expand into the operational [`SigningKey`] and its [`VerifyingKey`], using
            /// ML-DSA.KeyGen_internal (FIPS 204 Algorithm 6).
            ///
            /// Both keys fall out of the same expansion, so getting them together is free.
            /// The expansion itself is not: it costs about as much as producing a signature.
            /// Callers that sign more than once should hold on to the expanded key rather
            /// than expanding the seed again each time.
            pub fn expand(&self) -> (SigningKey, VerifyingKey) {
                let mut public = [0u8; PUBLIC_KEY_LENGTH];
                let mut expanded = vec![0u8; $sk_len].into_boxed_slice();
                let rc = unsafe {
                    $keypair(public.as_mut_ptr(), expanded.as_mut_ptr(), self.0.as_ptr())
                };
                assert_eq!(rc, 0, "key expansion failed");
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

        #[doc = concat!("An ML-DSA-", $level, " operational signing key: the expanded")]
        /// signing key that [`SigningKeySeed::expand`] produces, alongside the matching
        /// [`VerifyingKey`]. It keeps neither the seed nor the public key, and it has no
        /// serialized form. Serialize the seed instead. Zeroized on drop.
        ///
        /// The key lives on the heap rather than inline for one specific reason: the C
        /// writes it straight to its final address, and moving the key afterwards never
        /// copies secret bytes onto the stack where zeroization could not reach them.
        pub struct SigningKey {
            expanded: Box<[u8]>,
        }

        impl SigningKey {
            /// Sign `message` under the context string `ctx`, with the caller supplying the
            /// hedging randomness `rnd` (FIPS 204 Algorithm 2).
            ///
            /// Draw `rnd` fresh for every signature. That is what buys the hedged variant's
            /// resistance to fault attacks and to randomness reuse, and reusing a value
            /// across signatures gives it up. Passing all zeros is not a mistake; it selects
            /// FIPS 204's deterministic variant on purpose.
            ///
            /// `rnd` is not a secret, so it is not zeroized.
            pub fn sign(
                &self,
                message: &[u8],
                ctx: &[u8],
                rnd: &[u8; RND_LENGTH],
            ) -> Result<Signature, Error> {
                let (prefix, prefix_len) = domain_separation_prefix(ctx)?;
                let mut sig = [0u8; SIGNATURE_LENGTH];
                let rc = unsafe {
                    $signature(
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
                assert_eq!(rc, 0, "signing failed");
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

        #[doc = concat!("An ML-DSA-", $level, " public key.")]
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

            /// Verify `signature` over `message` under the context string `ctx` (FIPS 204
            /// Algorithm 3).
            ///
            /// Every failure comes back as `InvalidSignature`, with no further detail. The
            /// C reports a malformed encoding and an ordinary mismatch through the same
            /// code, and telling them apart would only hand information to whoever supplied
            /// the signature.
            pub fn verify(
                &self,
                message: &[u8],
                ctx: &[u8],
                signature: &Signature,
            ) -> Result<(), Error> {
                if ctx.len() > crate::MAX_CONTEXT_LENGTH {
                    return Err(Error::ContextTooLong);
                }
                let rc = unsafe {
                    $verify(
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

        // A derived Debug would print the whole key. A short prefix is enough to tell two
        // keys apart in test output, which is all this is for.
        impl fmt::Debug for VerifyingKey {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "VerifyingKey(")?;
                for byte in &self.0[..8] {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, "…)")
            }
        }

        #[doc = concat!("An ML-DSA-", $level, " signature.")]
        #[derive(Clone, PartialEq, Eq)]
        pub struct Signature([u8; SIGNATURE_LENGTH]);

        impl Signature {
            /// Parse a signature from exactly [`SIGNATURE_LENGTH`] bytes.
            ///
            /// This checks the length and nothing else. Whether the signature is any good
            /// is decided by [`VerifyingKey::verify`].
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
    };
}

pub(crate) use define_level;
