// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Minimal <string.h> shim for wasm32-unknown-unknown, which has no libc.
//
// mldsa-native includes <string.h> for the standard memory functions.
// packing.c includes it directly, so MLD_CONFIG_CUSTOM_MEMCPY/MEMSET alone
// cannot remove the header dependency.
//
// This header is only added to the include path for wasm32 and provides the
// declarations needed by the freestanding build. The implementations are
// supplied by Rust's compiler_builtins; no C libc is linked.

#ifndef MYSTEN_MLDSA_WASM32_STRING_H
#define MYSTEN_MLDSA_WASM32_STRING_H

#include <stddef.h>

void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);

#endif