/*
 * Copyright (c) 2022, Mysten Labs, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Single-level (ML-DSA-65) build with x86_64 runtime dispatch: identical to compiling
 * mldsa_native.c directly (the parameter set still arrives via build.rs defines), plus the
 * capability-probe injection that gates the AVX2 backends per CPU. Used only for x86_64
 * builds with the native feature; every other build compiles mldsa_native.c unchanged.
 */

/* build.rs defines this whenever it compiles the dispatch machinery; failing here catches
 * a build.rs refactor that drops the define while a shim still expects to gate on it. */
#if !defined(MLD_BUILD_X86_64_DISPATCH)
#error "single_level_x86_64.c compiled without MLD_BUILD_X86_64_DISPATCH; see build.rs"
#endif

/*
 * The runtime probe can only guard the hand-written kernels. If the compiler is itself
 * allowed to target AVX2, it emits AVX2 into this unguarded C (auto-vectorization, inlined
 * memcpy), and a pre-AVX2 CPU then dies with SIGILL before the probe can say no -- silently
 * voiding the feature's entire safety story. build.rs never passes an arch flag, but
 * environment CFLAGS are appended after its flags and would win, so refuse to build rather
 * than emit a binary that is unsafe on the machines this dispatch exists to protect.
 *
 * If you are deliberately targeting AVX2-only hardware, drop the `native` feature (the
 * portable C is always safe) or build without the arch flag and let the probe do its job.
 */
#if defined(__AVX2__)
#error "the C must not be compiled with AVX2 enabled (-mavx2/-march=...): it would put ungated AVX2 in the portable fallback path. See src/single_level_x86_64.c"
#endif

#include "native_dispatch.h"
#include "mldsa_native.c"

/* The Rust probe (src/capability.rs) hard-codes capability 0 as "AVX2" without seeing
 * upstream's mld_sys_cap enum. This pins the enum position: a re-pin that reorders
 * mld_sys_cap fails here at compile time instead of silently misrouting the probe. */
typedef char mld_assert_avx2_cap_is_zero[(MLD_SYS_CAP_X86_64_AVX2 == 0) ? 1 : -1];

/* The whole point of the native feature is that the assembly backend is actually
 * selected. build.rs enables it by defining MLD_SYS_X86_64_AVX2 (the macro upstream's
 * sys.h normally derives from __AVX2__); if a re-pin renames either macro, the build
 * would otherwise fall back to portable C silently and only a benchmark would notice. */
#if !defined(MLD_ARITH_BACKEND_X86_64_DEFAULT)
#error "native feature requested but the x86_64 AVX2 backend was not selected; see build.rs"
#endif
