# Provenance

`deps/mldsa-native` is a git submodule tracking
[pq-code-package/mldsa-native](https://github.com/pq-code-package/mldsa-native)
(Linux Foundation / Post-Quantum Cryptography Alliance), a CBMC- and
valgrind-verified C90 implementation of ML-DSA (FIPS 204).

- **Pinned commit:** `834a90d5e846ffa1e1611bd24e160bb2e9b86d35` (2026-08-06,
  `git describe`: `v2.0.0`)
- **License:** Apache-2.0 OR ISC OR MIT (see `deps/mldsa-native/LICENSE`)
- **Local modifications:** **none.** The submodule is consumed exactly as
  pinned; all configuration happens through `MLD_CONFIG_*` defines in
  `build.rs`. Any future patch requirement must instead be reported (and fixed)
  upstream.

This is upstream's first stable release. It is numbered `v2.0.0` rather than
`v1.0.0` to line up with the sister project `mlkem-native`. Therefore, the jump
from our previous pin (`v1.0.0-beta2-161`) is not the API break the version
numbers suggest: every breaking change listed in upstream's release notes landed
before that pin and was absorbed when this crate was first written.

What the release adds over the previous pin is assurance rather than code. Both
formal-verification efforts are now complete: the AArch64 (Neon) and x86_64
(AVX2) backends are proved functionally correct and memory-safe at the
object-code level in HOL Light with s2n-bignum, and CBMC covers the C. Every
routine except the two secret-vector rejection samplers is also proved to have
secret-independent timing.

Pin the tag rather than upstream `main`. Commits after `v2.0.0` include a
reshuffle of `mldsa_native_config.h` that no released version stands behind.

## Building

The submodule is not checked out automatically by `git clone`:

```bash
git submodule update --init
```

## Updating the pin

```bash
cd deps/mldsa-native
git fetch origin
git checkout <new-commit-or-tag>

# The new pin must be reachable from upstream main - never a PR or fork commit:
git branch -r --contains HEAD | grep -q origin/main

git describe --tags

cd ../..
git add deps/mldsa-native
```

Then update the commit hash, date, and `git describe` string above, confirm the
**"local modifications: none"** statement still holds, and re-run the full test
suite.

A prototype or size change upstream fails the build via `src/abi_check.c`.
Resolve it by updating `src/sys.rs` and `abi_check.c` together, never by
silently accepting the drift. This is not hypothetical: upstream removed the
`size_t *siglen` parameter from `signature_internal` between `v1.0.0-beta2-93`
and `v1.0.0-beta2-137`.

The re-pin to `v2.0.0` was checked this way, and it is worth repeating rather
than trusting a green test run: the compiled artifacts were compared against the
previous pin. The assembly archive came out byte-identical, and the C archives
disassembled to an identical instruction stream, so the two pins build the same
code. Passing tests alone would not have shown that.
