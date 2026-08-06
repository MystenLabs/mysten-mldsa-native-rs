// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Runtime CPU probe for the native backends.
//!
//! The vendored C asks "may I use this CPU feature?" through
//! `mld_sys_check_capability()`; `native_dispatch.h` routes that call to the
//! function below. Detection and caching come from the `cpufeatures` crate,
//! so after the first call each answer is one atomic load.
//!
//! The capability numbers are positions in upstream's `mld_sys_cap` enum;
//! the single_level_*.c shims verify them at compile time.

use core::ffi::c_int;

#[cfg(target_arch = "x86_64")]
cpufeatures::new!(cpuid_avx2, "avx2");

/// Called from the vendored C. 1 = supported, 0 = fall back to portable code.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn mysten_mldsa_sys_check_capability(cap: c_int) -> c_int {
    // 0 = MLD_SYS_CAP_X86_64_AVX2. cpufeatures also checks OSXSAVE/XCR0, so
    // "yes" means the OS saves the YMM registers too.
    (cap == 0 && cpuid_avx2::init().get()) as c_int
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android", target_vendor = "apple")
))]
cpufeatures::new!(cpuid_sha3, "sha3");

/// Called from the vendored C. 1 = supported, 0 = fall back to portable code.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn mysten_mldsa_sys_check_capability(cap: c_int) -> c_int {
    match cap {
        // 1 = MLD_SYS_CAP_AARCH64_NEON: baseline on aarch64, always yes.
        // Returning 0 would quietly turn the native backend into portable C.
        1 => 1,
        // 2 = MLD_SYS_CAP_AARCH64_SHA3: HWCAP on Linux/Android, sysctl on
        // Apple. Other OSes have no probe and claim nothing.
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        2 => cpuid_sha3::init().get() as c_int,
        _ => 0,
    }
}

/// Stub for targets with no native backend; the C never asks here.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[no_mangle]
pub extern "C" fn mysten_mldsa_sys_check_capability(_cap: c_int) -> c_int {
    0
}
