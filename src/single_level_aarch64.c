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
