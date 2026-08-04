/*
 * Copyright (c) 2022, Mysten Labs, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Runtime capability check for the aarch64 native backend.
 *
 * NEON is baseline on aarch64, so it needs no check. FEAT_SHA3 (the ARMv8.4-A
 * EOR3/RAX1/XAR/BCAX instructions used by the fast Keccak kernels) is NOT
 * baseline: Apple silicon and Neoverse V1/N2 have it, Neoverse N1 (AWS
 * Graviton2), Cortex-A72 and most pre-8.4 cores do not.
 *
 * This matters because the compiler decides at build time whether those
 * kernels are compiled in (upstream gates them on __ARM_FEATURE_SHA3, which
 * Apple's clang defines by default), while the CPU that runs the binary is
 * decided later. Upstream's default capability function assumes build host ==
 * run host and answers "supported" unconditionally, so without this file a
 * binary built on an SHA3-capable machine executes SHA3 instructions on every
 * aarch64 CPU and dies with SIGILL on the ones that lack the extension.
 *
 * Only the capabilities upstream's aarch64 backend actually queries are
 * answered here; anything else reports unsupported so the portable C runs.
 */

int mysten_mldsa_sys_check_capability(int cap);

#if defined(__aarch64__) || defined(_M_ARM64)

#if defined(__linux__)
#include <sys/auxv.h>
/* Not in older glibc headers; the value is ABI-fixed by the kernel. */
#ifndef HWCAP_SHA3
#define HWCAP_SHA3 (1 << 17)
#endif
#elif defined(__APPLE__)
#include <stddef.h>
#include <sys/sysctl.h>
#endif

static int mysten_mldsa_probe_sha3(void)
{
#if defined(__linux__)
  return (getauxval(AT_HWCAP) & HWCAP_SHA3) != 0;
#elif defined(__APPLE__)
  /* This key and upstream's "v84a" kernel files mean the same FEAT_SHA3:
   * Apple names it after Armv8.2, where it first appeared as an option;
   * upstream names it after Armv8.4, where it became common. */
  int present = 0;
  size_t len = sizeof(present);
  if (sysctlbyname("hw.optional.armv8_2_sha3", &present, &len, NULL, 0) != 0)
  {
    return 0;
  }
  return present != 0;
#else
  /* No probe available on this OS: claim nothing, run the scalar/portable
   * Keccak. NEON below is unaffected. */
  return 0;
#endif
}

/* Cached because the backend asks on every gated kernel call. The cache has
 * no lock, and that is safe here for the same reasons as in
 * capability_x86_64.c: every thread computes and stores the same answer, and
 * an aligned int store cannot be seen half-written on aarch64.
 * 0 = not probed yet, 1 = no SHA3, 2 = SHA3. */
static int mysten_mldsa_sha3_state = 0;

int mysten_mldsa_sys_check_capability(int cap)
{
  /* 1 and 2 are positions in upstream's mld_sys_cap enum. This file cannot
   * include sys.h to use the enum names, so single_level_aarch64.c checks at
   * compile time that the positions are still 1 and 2 (the
   * mld_assert_aarch64_*_cap typedefs). */
  if (cap == 1) /* MLD_SYS_CAP_AARCH64_NEON */
  {
    /* Every aarch64 CPU has NEON, so the answer is always yes. The branch
     * still matters: upstream asks before every arithmetic kernel call, and
     * returning 0 here would quietly make the whole native backend run as
     * portable C. */
    return 1;
  }
  if (cap != 2) /* MLD_SYS_CAP_AARCH64_SHA3 is the only other one queried. */
  {
    return 0;
  }
  if (mysten_mldsa_sha3_state == 0)
  {
    mysten_mldsa_sha3_state = mysten_mldsa_probe_sha3() ? 2 : 1;
  }
  return mysten_mldsa_sha3_state == 2;
}

#else /* !aarch64 */

int mysten_mldsa_sys_check_capability(int cap)
{
  (void)cap;
  return 0;
}

#endif /* !aarch64 */
