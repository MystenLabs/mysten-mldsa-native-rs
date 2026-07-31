/*
 * Copyright (c) 2022, Mysten Labs, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Runtime CPU dispatch for the x86_64 native backends.
 */

#define MLD_CONFIG_CUSTOM_CAPABILITY_FUNC
#define mld_sys_check_capability(cap) mysten_mldsa_sys_check_capability((int)(cap))
int mysten_mldsa_sys_check_capability(int cap);
