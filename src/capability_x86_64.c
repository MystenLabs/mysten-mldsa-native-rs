/*
 * Copyright (c) 2022, Mysten Labs, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Runtime CPU capability probe backing native_dispatch.h. Compiled only for x86_64 builds
 * with the native feature; see build.rs.
 *
 * The probe is raw cpuid/xgetbv instead of __builtin_cpu_supports: the builtin drags in a
 * libgcc/compiler-rt runtime symbol (__cpu_model) that not every link has, and it does not
 * everywhere confirm that the OS saves YMM state on context switches. Using AVX2 requires
 * all three of: the CPU flag, OSXSAVE, and XCR0 reporting XMM+YMM state enabled - the
 * sequence below is Intel's documented detection order.
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
