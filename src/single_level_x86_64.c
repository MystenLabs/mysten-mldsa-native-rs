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

#include "native_dispatch.h"
#include "mldsa_native.c"

/* capability_x86_64.c hard-codes capability 0 as "AVX2" without seeing upstream's
 * mld_sys_cap enum (a standalone TU cannot include sys.h without the whole config). This
 * pins the enum position: a re-pin that reorders mld_sys_cap fails here at compile time
 * instead of silently misrouting the probe. */
typedef char mld_assert_avx2_cap_is_zero[(MLD_SYS_CAP_X86_64_AVX2 == 0) ? 1 : -1];
