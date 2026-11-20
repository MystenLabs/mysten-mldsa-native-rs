// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Builds the vendored mldsa-native library (git submodule at `deps/mldsa-native`; see
//! `PROVENANCE.md` for the pinned commit) for the ML-DSA-65 parameter set.
//!
//! There are two implementations:
//!
//! - Portable C: always available and works on every supported target.
//! - Native backend: uses architecture-specific assembly for better performance.
//!   On AArch64 this is the NEON backend. On x86_64 this is the AVX2 backend.
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
//! - aarch64: NEON is baseline hardware, so the arithmetic backend is selected at compile
//!   time. FEAT_SHA3 (the ARMv8.4-A Keccak kernels) is not baseline, and the compiler pulls
//!   it in whenever it defines `__ARM_FEATURE_SHA3`, Apple's clang does so by default, so
//!   those kernels are gated behind a runtime HWCAP/sysctl probe (src/capability.rs).
//!   Without it, a binary built on an SHA3-capable host SIGILLs on a Neoverse N1 (Graviton2)
//!   or Cortex-A72 class CPU, because upstream's default capability hook assumes the build
//!   host and the run host are the same machine.
//! - x86_64: AVX2 is not baseline, so the backend is compiled in but every kernel call is
//!   gated behind a runtime CPU probe (native_dispatch.h + src/capability.rs); machines
//!   without AVX2 run the portable C. The C is deliberately compiled *without* `-mavx2`:
//!   the AVX2 code must stay confined to the probe-gated hand-written kernels, and an
//!   arch flag would let the compiler emit AVX2 into the unguarded C (auto-vectorization,
//!   memcpy expansion), crashing pre-AVX2 machines. The backend is enabled by defining
//!   `MLD_SYS_X86_64_AVX2` directly instead - the same macro upstream's sys.h derives
//!   from `__AVX2__`. If a re-pin renames either macro, single_level_x86_64.c notices
//!   that no backend got selected and fails the compile.
//! - Elsewhere (and under MSVC, which can neither assemble the GAS-syntax asm bundle nor
//!   call the SysV-ABI kernels): the portable C builds with a cargo warning.
//! - wasm32-unknown-unknown: portable C built freestanding because the target has no C library.
//!   A minimal `<string.h>` shim satisfies mldsa-native's header dependency, with the `mem*`
//!   implementations supplied by Rust's `compiler_builtins`.
//!
//! Outputs are identical across backends; the pinned seed->key and fixed-rnd signing
//! tests check it under every backend CI runs, including a native build whose probe is
//! forced to answer "no" (`--cfg mysten_mldsa_force_fallback`, see src/capability.rs).
//!
//! `MLD_CONFIG_NO_RANDOMIZED_API` removes mldsa-native's API variants that obtain
//! randomness themselves. This crate always passes randomness (seed / rnd) explicitly
//! across the FFI boundary, so the vendored C never needs to call a random-number
//! generator, and no `randombytes` symbol exists at link time.
//!
//! `MLD_CONFIG_INTERNAL_API_QUALIFIER=static` rides on the single-translation-unit shape:
//! internal helpers become `static`, so the C exports only the public API. The assembly
//! kernels cannot be `static`, so a native build exports those as well. Every exported name
//! carries `NAMESPACE_PREFIX` below instead of upstream's default, so another copy of
//! mldsa-native in the same link cannot collide with this one.
//!
//! The code is compiled as C99 to match upstream's CI. MSVC ignores the C99 flag, which is
//! harmless because upstream keeps the code C90-compatible.
//!
//! The way this build drives the vendored C follows AWS-LC; configure the C through
//! `MLD_CONFIG_*` defines rather than patching it, replace the capability hook with
//! our own CPU check, and compile the C without arch flags so vector code stays inside the
//! probe-gated assembly.

use std::path::PathBuf;

/// Prefix of every symbol the C and the assembly export, in the shape of upstream's
/// default `PQCP_MLDSA_NATIVE_MLDSA65`. `sys.rs` and `abi_check.c` spell the resulting
/// names out, so change all three together.
const NAMESPACE_PREFIX: &str = "MYSTEN_MLDSA_NATIVE_MLDSA65";

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

    // Test-only switch read by src/capability.rs; declared here so rustc knows the name.
    println!("cargo:rustc-check-cfg=cfg(mysten_mldsa_force_fallback)");

    let native = std::env::var_os("CARGO_FEATURE_NATIVE").is_some();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_endian = std::env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_default();
    let target_vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
    // The asm bundle is GAS syntax and its x86_64 kernels use the SysV calling convention;
    // MSVC handles neither, so native there falls back to the portable C.
    let gnu_compatible_cc = target_env != "msvc";
    // Upstream's NEON backend is little-endian only (sys.h checks __AARCH64EL__). With
    // this endian check, a big-endian aarch64 build gets portable C plus the warning
    // below; without it, it would fail on the shim's backend-selected #error.
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
        .define("MLD_CONFIG_NAMESPACE_PREFIX", NAMESPACE_PREFIX)
        .std("c99");

    // Signing keeps about 70 KiB of temporaries in one stack frame. A frame that large can
    // step over a guard page without touching it, so ask for the stack probes that clang
    // on Linux leaves off by default. Apple and Windows targets always probe.
    if std::env::var_os("CARGO_CFG_UNIX").is_some()
        && target_vendor != "apple"
        && target_arch != "wasm32"
    {
        build.flag_if_supported("-fstack-clash-protection");
    }

    // wasm32-unknown-unknown has no C library. Build the portable backend
    // freestanding and provide the small set of libc declarations it needs
    // through src/wasm32-freestanding. The corresponding mem* symbols are
    // supplied by Rust's compiler_builtins at link time.
    let freestanding_include = manifest_dir.join("src/wasm32-freestanding");
    if target_arch == "wasm32" {
        build
            .flag("-ffreestanding")
            .flag("-isystem")
            .flag(freestanding_include.to_str().unwrap());
    }

    // Native builds go through a thin per-architecture wrapper that routes upstream's
    // capability question to the Rust probe (src/capability.rs); everything else compiles
    // the upstream single-compilation-unit directly. Both architectures need the probe,
    // for different reasons: on x86_64 the AVX2
    // arithmetic backend is not baseline, and on aarch64 NEON is but the ARMv8.4-A FEAT_SHA3
    // Keccak kernels are not (Apple clang defines __ARM_FEATURE_SHA3 by default, so they get
    // compiled in and would SIGILL on a Neoverse N1 / Cortex-A72 class CPU).
    if native_x86_64 {
        build.file(manifest_dir.join("src/single_level_x86_64.c"));
    } else if native_aarch64 {
        build.file(manifest_dir.join("src/single_level_aarch64.c"));
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
        if native_aarch64 {
            build.define("MLD_BUILD_AARCH64_DISPATCH", None);
        }
        if native_x86_64 {
            // Enables the AVX2 backend without letting the compiler itself emit AVX2; see
            // the module comment. MLD_BUILD_X86_64_DISPATCH marks builds carrying the
            // dispatch machinery: single_level_x86_64.c asserts it, and a multilevel
            // shim would gate its native_dispatch.h include on it.
            build
                .define("MLD_SYS_X86_64_AVX2", None)
                .define("MLD_BUILD_X86_64_DISPATCH", None);
        }
        // One assembly unit covers every level; for multilevel builds upstream compiles it
        // with MLD_CONFIG_MULTILEVEL_WITH_SHARED (see examples/monolithic_build_multilevel_native).
        // It needs the same namespace prefix as the C that calls into it.
        let mut asm = cc::Build::new();
        asm.file(src.join("mldsa_native_asm.S"))
            .include(&src)
            .define("MLD_CONFIG_USE_NATIVE_BACKEND_ARITH", None)
            .define("MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202", None)
            .define("MLD_CONFIG_NAMESPACE_PREFIX", NAMESPACE_PREFIX)
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
        "src/single_level_x86_64.c",
        "src/single_level_aarch64.c",
        "src/wasm32-freestanding/string.h",
    ] {
        println!("cargo:rerun-if-changed={}", manifest_dir.join(f).display());
    }
}
