/*
 * Copyright (c) 2022, Mysten Labs, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Runtime AVX2 capability check for the x86_64 native backend.
 * Why do we need this?
 * x86_64 does not guarantee AVX2. A binary built with the native backend
 * therefore needs to support two kinds of machines:
 *
 *     AVX2 CPU     -> use the fast AVX2 kernels
 *     no AVX2 CPU  -> use the portable C implementation
 *
 * This file answers one question:
 *     "Can this process safely execute AVX2 instructions?"
 * 
 * Checking the CPU alone is not enough. AVX2 also requires the operating
 * system to support saving/restoring the extended XMM/YMM register state.
 * We therefore perform the standard three-part check:
 *
 *     1. CPUID says the OS supports XSAVE/XGETBV.
 *     2. XCR0 says the OS has enabled XMM + YMM state.
 *     3. CPUID says the CPU supports AVX2.
 *
 * The result is cached because CPUID/XGETBV are relatively expensive and
 * the ML-DSA implementation may ask about the capability many times during
 * a single signature.
 *
 * This file is only useful for GCC/Clang x86_64 builds. Other targets simply
 * report that the capability is unavailable and use portable C.
 */


int mysten_mldsa_sys_check_capability(int cap);

#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)

#include <cpuid.h>

static int mysten_mldsa_probe_avx2(void)
{
  unsigned int eax, ebx, ecx, edx;
  /* OSXSAVE: leaf 1, ECX bit 27 - xgetbv is only legal once this is set. */
  if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx) || !(ecx & (1u << 27)))
  {
    return 0;
  }
  /* XCR0 bits 1 and 2: the OS saves XMM and YMM state. */
  __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0u));
  if ((eax & 0x6u) != 0x6u)
  {
    return 0;
  }
  /* AVX2: leaf 7 subleaf 0, EBX bit 5. The max-leaf check is explicit and the query uses
   * the __cpuid_count macro because the __get_cpuid_count helper that combines them is
   * missing from <cpuid.h> in GCC <= 6 and clang < 5. */
  if (__get_cpuid_max(0, 0) < 7)
  {
    return 0;
  }
  __cpuid_count(7, 0, eax, ebx, ecx, edx);
  return (ebx & (1u << 5)) != 0;
}

/* mldsa-native asks for the capability on every gated kernel call - hundreds of times per
 * signature - and cpuid/xgetbv are serializing instructions, so the answer is computed
 * once and cached. The unsynchronized cache is safe: the probe is idempotent, every
 * thread stores the same value, and an aligned int store does not tear on x86_64.
 * 0 = not probed yet, 1 = no AVX2, 2 = AVX2. */
static int mysten_mldsa_avx2_state = 0;

int mysten_mldsa_sys_check_capability(int cap)
{
  /* 0 is MLD_SYS_CAP_X86_64_AVX2, the only capability the x86_64 backend queries;
   * single_level_x86_64.c pins that enum position at compile time. */
  if (cap != 0)
  {
    return 0;
  }
  if (mysten_mldsa_avx2_state == 0)
  {
    mysten_mldsa_avx2_state = mysten_mldsa_probe_avx2() ? 2 : 1;
  }
  return mysten_mldsa_avx2_state == 2;
}

#else /* !((__GNUC__ || __clang__) && __x86_64__) */

int mysten_mldsa_sys_check_capability(int cap)
{
  /* No probe available: claim nothing, run portable C. */
  (void)cap;
  return 0;
}

#endif /* !((__GNUC__ || __clang__) && __x86_64__) */
