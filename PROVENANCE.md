# Provenance

`deps/mldsa-native` is a git submodule tracking
[pq-code-package/mldsa-native](https://github.com/pq-code-package/mldsa-native)
(Linux Foundation / Post-Quantum Cryptography Alliance), a CBMC- and
valgrind-verified C90 implementation of ML-DSA (FIPS 204).

- Pinned commit: `c2128e953209a8b2420d521af63a77c481cac370` (2026-08-05,
  `git describe`: `v1.0.0-beta2-161-gc2128e95`)
- License: Apache-2.0 OR ISC OR MIT (see `deps/mldsa-native/LICENSE`)
- Local modifications: **none.** The submodule is consumed exactly as pinned;
  all configuration happens through `MLD_CONFIG_*` defines in `build.rs`. Any
  future patch requirement must instead be reported (and fixed) upstream.

mldsa-native's v1.0.0 stable release is in progress upstream
([PR #1299](https://github.com/pq-code-package/mldsa-native/pull/1299)).
This pin predates it deliberately, to pick up fixes and the completed
AArch64/x86_64 HOL Light proofs since the last tagged release
(`v1.0.0-beta2`). Re-pin to `v1.0.0` once it is tagged upstream.

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
"local modifications: none" statement still holds, and re-run the full test
suite. A prototype or size change upstream fails the build via
`src/abi_check.c` - resolve it by updating `src/sys.rs` and `abi_check.c`
together, never by silently accepting the drift. (This is not hypothetical:
upstream removed the `size_t *siglen` parameter from `signature_internal`
between `v1.0.0-beta2-93` and `v1.0.0-beta2-137`.)
