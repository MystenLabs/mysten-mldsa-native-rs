/*
 * Copyright (c) 2022, Mysten Labs, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Runtime CPU dispatch for the native backends.
 *
 * mldsa-native asks "may I use this CPU feature?" through mld_sys_check_capability().
 * By default that function answers from compile-time flags, which assumes the machine
 * that built the binary is the machine that runs it. MLD_CONFIG_CUSTOM_CAPABILITY_FUNC
 * is the upstream-supported way to replace it, and this header does exactly that: every
 * capability question is routed to our own probe instead.
 *
 * Based on how AWS-LC vendors the same library: their
 * crypto/fipsmodule/ml_dsa/mldsa_native_config.h sets the identical macro and points
 * mld_sys_check_capability() at CRYPTO_is_AVX2_capable(), their existing CPU-feature
 * machinery. We have no libcrypto to borrow from, so ours points at the Rust probe in
 * src/capability.rs instead. Same hook, different backing implementation; no AWS-LC
 * code is directly used in this crate.
 */

#define MLD_CONFIG_CUSTOM_CAPABILITY_FUNC
#define mld_sys_check_capability(cap) mysten_mldsa_sys_check_capability((int)(cap))
int mysten_mldsa_sys_check_capability(int cap);
