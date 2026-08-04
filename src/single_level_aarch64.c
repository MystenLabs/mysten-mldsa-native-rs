/*
 * Copyright (c) 2022, Mysten Labs, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Single-level (ML-DSA-65) build with aarch64 runtime dispatch: identical to
 * compiling mldsa_native.c directly (the parameter set still arrives via
 * build.rs defines), plus the capability-probe injection that gates the
 * ARMv8.4-A FEAT_SHA3 Keccak kernels per CPU. See capability_aarch64.c for why
 * NEON needs no gate but SHA3 does.
 */

/* build.rs defines this whenever it compiles the aarch64 dispatch machinery;
 * failing here catches a build.rs refactor that drops the define. */
#if !defined(MLD_BUILD_AARCH64_DISPATCH)
#error "single_level_aarch64.c compiled without MLD_BUILD_AARCH64_DISPATCH; see build.rs"
#endif

/*
 * Same protection as the __AVX2__ check in single_level_x86_64.c. The runtime
 * probe only guards the hand-written SHA3 kernels. If CFLAGS raise the target
 * architecture (-march=armv8.2-a+sha3 or later), the compiler may also use
 * SHA3-era instructions in the plain C, including the fallback path the probe
 * cannot protect. A CPU without SHA3 (Graviton2, Cortex-A72) then crashes with
 * SIGILL. So refuse to build. Like the x86_64 check, this catches the most
 * likely bad flag, not every possible one.
 *
 * Exception: on macOS and Mac Catalyst, clang defines __ARM_FEATURE_SHA3 on
 * its own, and every CPU those systems run on (M1 and newer) has SHA3, so
 * there is nothing to protect and the error would block every Mac build.
 * iOS gets no exception: older iPhone CPUs (up to the A12) have no SHA3, and
 * clang does not define the macro there unless CFLAGS force it.
 */
#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif
#if defined(__ARM_FEATURE_SHA3) && \
    !(defined(__APPLE__) && (TARGET_OS_OSX || TARGET_OS_MACCATALYST))
#error "the C must not be compiled with SHA3 enabled (-march=...+sha3): it would put SHA3-era instructions in the portable fallback path. See src/single_level_aarch64.c"
#endif

#include "native_dispatch.h"
#include "mldsa_native.c"

/* capability_aarch64.c hard-codes the capability numbers without seeing
 * upstream's mld_sys_cap enum (a standalone TU cannot include sys.h without
 * the whole config). These pin the enum positions: a re-pin that reorders
 * mld_sys_cap fails here at compile time instead of silently misrouting the
 * probe -- which would be a SIGILL, not a slowdown. */
typedef char mld_assert_aarch64_neon_cap[(MLD_SYS_CAP_AARCH64_NEON == 1) ? 1 : -1];
typedef char mld_assert_aarch64_sha3_cap[(MLD_SYS_CAP_AARCH64_SHA3 == 2) ? 1 : -1];

/* The whole point of the native feature is that the assembly backend is
 * actually selected. Upstream sets this when its aarch64 arithmetic backend is
 * compiled in; if a re-pin renames the macros build.rs drives, the build would
 * otherwise fall back to portable C silently and only a benchmark would
 * notice. */
#if !defined(MLD_ARITH_BACKEND_AARCH64)
#error "native feature requested but the aarch64 arithmetic backend was not selected; see build.rs"
#endif
