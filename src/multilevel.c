/*
 * Copyright (c) 2022, Mysten Labs, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Multi-level single translation unit, following upstream's
 * examples/monolithic_build_multilevel (and AWS-LC's production ml_dsa.c): include the
 * single-compilation-unit source once per enabled parameter set. ML-DSA-65 is this
 * crate's always-on level, so it carries the level-independent code (FIPS202/Keccak,
 * shared helpers); the optional levels exclude it. Level-specific symbols are namespaced
 * per parameter set, so the sections cannot collide.
 *
 * Only compiled when the mldsa44 or mldsa87 cargo feature is on (see build.rs, which
 * translates the features into MLD_BUILD_LEVEL_* defines); the default build compiles
 * mldsa_native.c directly, unchanged. KEEP_SHARED_HEADERS stays defined throughout: it
 * only re-opens shared header guards for the next inclusion, and is inert after the last.
 */

/* In multilevel builds the namespacing machinery appends the parameter set (44/65/87)
 * itself, so the prefix must not embed it; this base yields exactly the same
 * PQCP_MLDSA_NATIVE_MLDSA65_* symbols as the default single-level build, keeping sys.rs
 * link names unchanged across both build shapes. */
#define MLD_CONFIG_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA

/* Native builds ask this crate's runtime probe about the CPU instead of upstream's default
 * hook, which assumes the machine that built the binary is the machine that runs it. One
 * include covers every level below, because the header only redirects a macro and the probe
 * itself lives in Rust (src/capability.rs), shared by all parameter sets. The single-level
 * shims do the same thing for the default build. */
#if defined(MLD_BUILD_X86_64_DISPATCH) || defined(MLD_BUILD_AARCH64_DISPATCH)
#include "native_dispatch.h"
#endif

#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS

#define MLD_CONFIG_MULTILEVEL_WITH_SHARED
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_CONFIG_MULTILEVEL_WITH_SHARED
#define MLD_CONFIG_MULTILEVEL_NO_SHARED

#if defined(MLD_BUILD_LEVEL_44)
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#endif /* MLD_BUILD_LEVEL_44 */

#if defined(MLD_BUILD_LEVEL_87)
#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#endif /* MLD_BUILD_LEVEL_87 */

/*
 * These are the same guards the single-level shims carry, repeated here on purpose: this
 * file replaces them in a multilevel build, so without the repetition the checks would
 * simply disappear the moment someone enables a second parameter set.
 *
 * The typedefs pin the capability numbers the probe files hard-code, so an upstream
 * renumbering is a build error rather than a question sent to the wrong answer. The
 * backend checks catch the opposite mistake: a renamed macro leaving the native feature
 * switched on but the assembly absent, which nothing except a benchmark would reveal.
 */
#if defined(MLD_BUILD_X86_64_DISPATCH)
typedef char mld_assert_avx2_cap_is_zero[(MLD_SYS_CAP_X86_64_AVX2 == 0) ? 1 : -1];
#if !defined(MLD_ARITH_BACKEND_X86_64_DEFAULT)
#error "native feature requested but the x86_64 AVX2 backend was not selected; see build.rs"
#endif
#if defined(__AVX2__)
#error "the C must not be compiled with AVX2 enabled (-mavx2/-march=...): it would put ungated AVX2 in the portable fallback path. See src/single_level_x86_64.c"
#endif
#endif /* MLD_BUILD_X86_64_DISPATCH */

#if defined(MLD_BUILD_AARCH64_DISPATCH)
typedef char mld_assert_aarch64_neon_cap[(MLD_SYS_CAP_AARCH64_NEON == 1) ? 1 : -1];
typedef char mld_assert_aarch64_sha3_cap[(MLD_SYS_CAP_AARCH64_SHA3 == 2) ? 1 : -1];
#if !defined(MLD_ARITH_BACKEND_AARCH64)
#error "native feature requested but the aarch64 arithmetic backend was not selected; see build.rs"
#endif
/* Same SHA3 CFLAGS check as single_level_aarch64.c; see there for the full why. */
#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif
#if defined(__ARM_FEATURE_SHA3) && \
    !(defined(__APPLE__) && (TARGET_OS_OSX || TARGET_OS_MACCATALYST))
#error "the C must not be compiled with SHA3 enabled (-march=...+sha3): it would put SHA3-era instructions in the portable fallback path. See src/single_level_aarch64.c"
#endif
#endif /* MLD_BUILD_AARCH64_DISPATCH */
