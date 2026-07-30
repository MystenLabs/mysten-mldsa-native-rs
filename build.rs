// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Builds the vendored mldsa-native library (git submodule at `deps/mldsa-native`; see
//! `PROVENANCE.md` for the pinned commit) for the ML-DSA-65 parameter set.
//!
//! The build intentionally mirrors upstream's monolithic build. mldsa-native is designed to
//! be compiled as a single translation unit: `mldsa_native.c` `#include`s every
//! implementation file, so exactly one file per build compiles it - either directly, or
//! through a thin wrapper in this crate's src/ that `#include`s it. If someone adds
//! upstream implementation files to this build as separate units, every function will be
//! defined twice and the link will fail.
//!
//! `src/abi_check.c` intentionally produces no code. Instead, it contains compile-time
//! checks that fail if a future update of mldsa-native changes the ABI we expose through
//! Rust FFI (function signatures or size constants). That catches incompatible upstream
//! changes during the build instead of at runtime.
//!
//! The default build compiles only the portable C implementation, which works on every
//! target. The `native` feature swaps in mldsa-native's formally verified assembly
//! backends where available:
//!
//! - aarch64: NEON is baseline hardware, so the backend is selected at compile time.
//! - x86_64: AVX2 is not baseline, so the backend is compiled in but every kernel call is
//!   gated behind a runtime CPU probe (native_dispatch.h + capability_x86_64.c); machines
//!   without AVX2 run the portable C. The C is deliberately compiled *without* `-mavx2`:
//!   the AVX2 code must stay confined to the probe-gated hand-written kernels, and an
//!   arch flag would let the compiler emit AVX2 into the unguarded C (auto-vectorization,
//!   memcpy expansion), crashing pre-AVX2 machines. The backend is enabled by defining
//!   `MLD_SYS_X86_64_AVX2` directly instead - the same macro upstream's sys.h derives
//!   from `__AVX2__`. If a re-pin renames that macro the backend silently deactivates
//!   (still correct, just portable-C speed), so re-pins must re-check it.
//! - Elsewhere (and under MSVC, which can neither assemble the GAS-syntax asm bundle nor
//!   call the SysV-ABI kernels): the portable C builds with a cargo warning.
//!
//! Outputs are identical across backends; the pinned seed->key and fixed-rnd signing
//! tests prove it.
//!
//! `MLD_CONFIG_NO_RANDOMIZED_API` removes mldsa-native's API variants that obtain
//! randomness themselves. This crate always passes randomness (seed / rnd) explicitly
//! across the FFI boundary, so the vendored C never needs to call a random-number
//! generator, and no `randombytes` symbol exists at link time.
//!
//! `MLD_CONFIG_INTERNAL_API_QUALIFIER=static` rides on the single-translation-unit shape:
//! internal helpers become `static`, so only the public API is exported and a symbol
//! collision with any other copy of mldsa-native under the default namespace is impossible.
//!
//! The code is compiled as C99 to match upstream's CI. MSVC ignores the C99 flag, which is
//! harmless because upstream keeps the code C90-compatible.

use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest_dir.join("deps/mldsa-native/mldsa");
    let abi_check = manifest_dir.join("src/abi_check.c");

    if !src.join("mldsa_native.c").exists() {
        panic!(
            "mldsa-native submodule not found at {}. Run `git submodule update --init` in the repo root.",
            src.display()
        );
    }

    let native = std::env::var_os("CARGO_FEATURE_NATIVE").is_some();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_endian = std::env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_default();
    // The asm bundle is GAS syntax and its x86_64 kernels use the SysV calling convention;
    // MSVC handles neither, so native there falls back to the portable C.
    let gnu_compatible_cc = target_env != "msvc";
    // Upstream's NEON backend is little-endian only (sys.h gates on __AARCH64EL__);
    // without the endian check, aarch64_be would silently build portable C while skipping
    // the warning below.
    let native_aarch64 =
        native && target_arch == "aarch64" && target_endian == "little" && gnu_compatible_cc;
    let native_x86_64 = native && target_arch == "x86_64" && gnu_compatible_cc;
    let native_enabled = native_aarch64 || native_x86_64;
    if native && !native_enabled {
        println!(
            "cargo:warning=the `native` feature currently accelerates aarch64 and x86_64 \
             with GNU-compatible toolchains only; building the portable C backend for \
             {target_arch}-{target_env}"
        );
    }

    let mut build = cc::Build::new();
    build
        .include(&src)
        .define("MLD_CONFIG_NO_RANDOMIZED_API", None)
        .define("MLD_CONFIG_INTERNAL_API_QUALIFIER", "static")
        .std("c99");

    // x86_64 native builds go through a thin wrapper that injects the runtime CPU
    // probe; everything else compiles the upstream single-compilation-unit directly.
    if native_x86_64 {
        build.file(manifest_dir.join("src/single_level_x86_64.c"));
    } else {
        build.file(src.join("mldsa_native.c"));
    }
    build
        .file(&abi_check)
        .define("MLD_CONFIG_PARAMETER_SET", "65");

    if native_enabled {
        build
            .define("MLD_CONFIG_USE_NATIVE_BACKEND_ARITH", None)
            .define("MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202", None);
        if native_x86_64 {
            // Enables the AVX2 backend without letting the compiler itself emit AVX2; see
            // the module comment. The probe compiles under the same AVX2-free flags, so it
            // cannot itself contain AVX2. MLD_BUILD_X86_64_DISPATCH marks builds carrying
            // the dispatch machinery: single_level_x86_64.c asserts it, and a multilevel
            // shim would gate its native_dispatch.h include on it.
            build
                .define("MLD_SYS_X86_64_AVX2", None)
                .define("MLD_BUILD_X86_64_DISPATCH", None)
                .file(manifest_dir.join("src/capability_x86_64.c"));
        }
        // One assembly unit covers every level; for multilevel builds upstream compiles it
        // with MLD_CONFIG_MULTILEVEL_WITH_SHARED (see examples/monolithic_build_multilevel_native).
        let mut asm = cc::Build::new();
        asm.file(src.join("mldsa_native_asm.S"))
            .include(&src)
            .define("MLD_CONFIG_USE_NATIVE_BACKEND_ARITH", None)
            .define("MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202", None)
            .define("MLD_CONFIG_PARAMETER_SET", "65");
        if native_x86_64 {
            // Same backend switch as the C side: hand-written mnemonics need no -mavx2,
            // but the kernels' preprocessor guards need the backend to be selected.
            asm.define("MLD_SYS_X86_64_AVX2", None);
        }
        asm.compile("mldsa_native_asm");
    }

    build.compile("mldsa65");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", abi_check.display());
    for f in [
        "src/native_dispatch.h",
        "src/capability_x86_64.c",
        "src/single_level_x86_64.c",
    ] {
        println!("cargo:rerun-if-changed={}", manifest_dir.join(f).display());
    }
}
