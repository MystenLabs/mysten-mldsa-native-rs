// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Raw FFI bindings to mldsa-native's ML-DSA-65 `_internal` API (see `../PROVENANCE.md`).
//!
//! This module is intentionally a thin translation of the C API. It performs no
//! validation or policy decisions: callers are responsible for providing
//! correctly formatted byte buffers, constructing any FIPS 204 message prefixes,
//! and supplying randomness where required.
//!
//! The library is built with `MLD_CONFIG_NO_RANDOMIZED_API` (see `build.rs`), so
//! the vendored C never obtains entropy itself. Every operation that requires
//! randomness instead takes it as an explicit pointer argument.
//!
//! # Safety
//!
//! For every function in this module:
//! - Every pointer must refer to a live buffer of the documented size.
//! - No two buffer arguments may overlap. This matches mldsa-native's verified
//!   CBMC contracts.
//! - Buffers are treated as byte arrays only; there are no alignment
//!   requirements.
//!
//! The function declarations here are mirrored in `abi_check.c`. If a future
//! update of mldsa-native changes one of the C function signatures, the build
//! fails instead of silently introducing an FFI ABI mismatch.

#![allow(non_camel_case_types)]

/// FIPS 204 parameters size
/// Generic consts:
pub const MLDSA_SEEDBYTES: usize = 32;
pub const MLDSA_RNDBYTES: usize = 32;
/// MLDSA65 specific ones:
pub const MLDSA65_PUBLICKEYBYTES: usize = 1952;
pub const MLDSA65_SECRETKEYBYTES: usize = 4032;
pub const MLDSA65_BYTES: usize = 3309;

extern "C" {
    /// Implements FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal).
    ///
    /// `pk` and `sk` must point to `MLDSA65_PUBLICKEYBYTES`/`MLDSA65_SECRETKEYBYTES` bytes;
    /// `seed` to `MLDSA_SEEDBYTES` bytes. Returns 0 on success.
    #[link_name = "MYSTEN_MLDSA_NATIVE_MLDSA65_keypair_internal"]
    pub fn mldsa65_keypair_internal(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;

    /// Implements FIPS 204 Algorithm 7 (ML-DSA.Sign_internal, `externalmu = 0`).
    ///
    /// `sig` must point to `MLDSA65_BYTES` bytes (fixed length; no output-length parameter).
    /// `pre` is the caller-constructed FIPS 204 message-prefix (`0x00 || ctxlen || ctx` for pure
    /// ML-DSA) and is not validated here; the C enforces `ctxlen <= 255` only on the verify
    /// path, so the signing caller owns that check. `rnd` is `MLDSA_RNDBYTES` of fresh
    /// randomness for hedged signing. `sk` must point to `MLDSA65_SECRETKEYBYTES` bytes and is
    /// assumed valid (mldsa-native does not validate secret keys on the signing path). Returns 0
    /// on success; on any nonzero return the C has zeroized `sig`.
    #[link_name = "MYSTEN_MLDSA_NATIVE_MLDSA65_signature_internal"]
    pub fn mldsa65_signature_internal(
        sig: *mut u8,
        m: *const u8,
        mlen: usize,
        pre: *const u8,
        prelen: usize,
        rnd: *const u8,
        sk: *const u8,
        externalmu: i32,
    ) -> i32;

    /// Implements FIPS 204 Algorithm 3 (ML-DSA.Verify).
    ///
    /// `sig` must point to `MLDSA65_BYTES` bytes, `pk` to `MLDSA65_PUBLICKEYBYTES` bytes; `ctx`
    /// may be NULL when `ctxlen` is 0 (upstream documents this). Verification needs no
    /// randomness. Returns 0 iff the signature verifies; nonzero also covers rejected encodings
    /// and `ctxlen > 255`, so callers must treat it as opaque failure, never classify it.
    #[link_name = "MYSTEN_MLDSA_NATIVE_MLDSA65_verify"]
    pub fn mldsa65_verify(
        sig: *const u8,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        pk: *const u8,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // FIPS 204's pure-ML-DSA message prefix: domain separator 0x00, then the (empty) context's
    // length, then the (empty) context itself. See Algorithm 2/3 in FIPS 204.
    const EMPTY_CONTEXT_PREFIX: [u8; 2] = [0x00, 0x00];

    #[test]
    fn keypair_sign_verify_smoke_test() {
        let seed = [7u8; MLDSA_SEEDBYTES];
        let mut pk = [0u8; MLDSA65_PUBLICKEYBYTES];
        let mut sk = [0u8; MLDSA65_SECRETKEYBYTES];
        let rc =
            unsafe { mldsa65_keypair_internal(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
        assert_eq!(rc, 0);
        assert_ne!(
            pk, [0u8; MLDSA65_PUBLICKEYBYTES],
            "keygen left pk untouched"
        );

        let msg = b"mysten-mldsa-native-rs sys smoke test";
        let rnd = [9u8; MLDSA_RNDBYTES];
        let mut sig = [0u8; MLDSA65_BYTES];
        let rc = unsafe {
            mldsa65_signature_internal(
                sig.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                EMPTY_CONTEXT_PREFIX.as_ptr(),
                EMPTY_CONTEXT_PREFIX.len(),
                rnd.as_ptr(),
                sk.as_ptr(),
                0,
            )
        };
        assert_eq!(rc, 0);
        assert_ne!(sig, [0u8; MLDSA65_BYTES], "signing left sig untouched");

        let rc = unsafe {
            mldsa65_verify(
                sig.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                pk.as_ptr(),
            )
        };
        assert_eq!(rc, 0, "valid signature failed to verify");

        let rc = unsafe {
            mldsa65_verify(
                sig.as_ptr(),
                b"wrong message".as_ptr(),
                13,
                std::ptr::null(),
                0,
                pk.as_ptr(),
            )
        };
        assert_ne!(rc, 0, "signature verified against the wrong message");
    }

    #[test]
    fn same_seed_same_keypair() {
        let seed = [42u8; MLDSA_SEEDBYTES];
        let mut pk1 = [0u8; MLDSA65_PUBLICKEYBYTES];
        let mut sk1 = [0u8; MLDSA65_SECRETKEYBYTES];
        let mut pk2 = [0u8; MLDSA65_PUBLICKEYBYTES];
        let mut sk2 = [0u8; MLDSA65_SECRETKEYBYTES];
        unsafe {
            assert_eq!(
                mldsa65_keypair_internal(pk1.as_mut_ptr(), sk1.as_mut_ptr(), seed.as_ptr()),
                0
            );
            assert_eq!(
                mldsa65_keypair_internal(pk2.as_mut_ptr(), sk2.as_mut_ptr(), seed.as_ptr()),
                0
            );
        }
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    /// Seeds whose key generation takes the rare branch of the secret-vector sampler. One
    /// secret polynomial gets fewer than 256 coefficients out of its first two SHAKE256
    /// blocks, which happens for about one key in 13,000. A third block is then squeezed
    /// and the portable C carries on from where the first pass stopped; in a native build
    /// that is the assembly sampler's partial output. No other seed in this crate's tests
    /// or vector files reaches that hand-over.
    ///
    /// `(seed prefix, zero-padded to 32 bytes; SHA-256 of the public key; SHA-256 of the
    /// expanded secret key)`. The secret key is pinned too because the public key keeps
    /// only the top bits of `t = A*s1 + s2`, so a wrong coefficient of `s2` rarely shows
    /// in it. The seeds and public-key digests come from the November 2026 review of this
    /// crate; OpenSSL 3.6 and 4.0 reproduce both columns.
    const SAMPLER_CONTINUATION_SEEDS: [(&[u8], &str, &str); 7] = [
        // s2[4]: 248 coefficients accepted in the first two blocks
        (
            &[0x4f, 0x27],
            "a667a37ffa29ddea3de5973c9aae6bbe6ee302a9352df28bdb1630f37e46b8aa",
            "e8ee217766704fda2eda58531809d1dcd12b0f69e140ed17d3db671a62cd5019",
        ),
        // s2[1]: 255
        (
            &[0x74, 0x39],
            "42a4e7598462af6f7cd7b0865066dc263e59cfb5b14dd156515d188e293053f2",
            "dd1c03eae7eb8f8e1bb08481aaaf3aabd048017008b6666658cbbb8e6d34e450",
        ),
        // s2[5]: 255
        (
            &[0xf6, 0x70],
            "a4d79e841a0d9095b1432026d46376236f3513a2f548914e03a533e998b71aac",
            "e7b1b50f7b0fc1dab211bb037187f98d7848416fdff84c4ac443e67df9106fd2",
        ),
        // s2[2]: 254
        (
            &[0xb5, 0x88],
            "6ff0044518c6355178d3c78d85aad9707d65deb755a860fa25188f6d79936c1e",
            "6cbf0ce9c45c0ac364cccf567e01d1b07a3f407ff044beaf118322575fb2a285",
        ),
        // s1[0]: 252
        (
            &[0x00, 0x35, 0xce],
            "0b4941623a78faa83f75b7fd1f835f5a6309710a622f53f543464fbd54595629",
            "10cc183b2f7cf7a1f4e1acb68ae32fcbc9129f33de1fe34d24b09d18c009f6e6",
        ),
        // s1[1]: 255
        (
            &[0x01, 0x89, 0x96],
            "2f3d0f938f9abee07b85ee9f03a2e9eaffd59565c1395ba7ff8e35f8f6f73e54",
            "fb7c43fc2602c8c5738c295cbd12356a7c202a4c4f7b696ad08f78d04ee95101",
        ),
        // s1[0]: 252
        (
            &[0x01, 0xd0, 0xa1],
            "1710a7a83ba45828413605e98da2ebfa718085cb26dd8bbc5f795dfb9696edac",
            "f02e5f98ed9f3a966eb33da4ddec0cca7665053ad5031dc7faf6218ef291722b",
        ),
    ];

    #[test]
    fn keygen_matches_reference_on_the_sampler_continuation_path() {
        for (prefix, pk_sha256, sk_sha256) in SAMPLER_CONTINUATION_SEEDS {
            let mut seed = [0u8; MLDSA_SEEDBYTES];
            seed[..prefix.len()].copy_from_slice(prefix);
            let mut pk = [0u8; MLDSA65_PUBLICKEYBYTES];
            let mut sk = [0u8; MLDSA65_SECRETKEYBYTES];
            let rc = unsafe {
                mldsa65_keypair_internal(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
            };
            assert_eq!(rc, 0);

            let label = hex::encode(prefix);
            assert_eq!(
                hex::encode(Sha256::digest(pk)),
                pk_sha256,
                "seed {label}: public key diverged"
            );
            assert_eq!(
                hex::encode(Sha256::digest(sk)),
                sk_sha256,
                "seed {label}: secret key diverged"
            );
        }
    }
}
