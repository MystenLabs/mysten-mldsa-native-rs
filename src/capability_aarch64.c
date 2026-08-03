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
 *
 * Same shape as capability_x86_64.c, which follows how AWS-LC vendors this
 * library. AWS-LC answers only the x86_64 question because it does not enable
 * the aarch64 backend, so the SHA3 probe below has no counterpart there.
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

/* Same caching rationale as capability_x86_64.c: the backend asks on every
 * gated kernel call. 0 = not probed yet, 1 = no SHA3, 2 = SHA3. */
static int mysten_mldsa_sha3_state = 0;

int mysten_mldsa_sys_check_capability(int cap)
{
  /* Positions pinned at compile time by the shim that includes this build;
   * see the mld_assert_aarch64_caps assertions. */
  if (cap == 1) /* MLD_SYS_CAP_AARCH64_NEON: architecture baseline. */
  {
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
