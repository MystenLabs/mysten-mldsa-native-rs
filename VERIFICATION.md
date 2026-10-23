# Verification record

What we ship: mldsa-native `v2.0.0`, commit `834a90d5e846ffa1e1611bd24e160bb2e9b86d35`
(2026-08-06), unpatched, as the submodule at `deps/mldsa-native` (see `PROVENANCE.md`).

Upstream's assurance rests on four CI jobs. We re-ran them ourselves on that commit with
`scripts/verify-upstream.sh`, which clones upstream at the pin, refuses a dirty tree or a wrong
origin, and runs the same stages with the same flags as upstream's workflows. No single host can run
every stage, so the record is two runs that cover each other.

| Stage | What it establishes | Linux x86_64 | macOS arm64 |
|---|---|---|---|
| conformance | functional tests, KATs, NIST ACVP and Wycheproof vectors, all three parameter sets, native backend | pass | pass |
| cbmc | memory safety, type safety and absence of undefined behaviour in the covered C, under upstream's proof assumptions; 210 proofs for ML-DSA-65 | pass, CBMC 6.10.0 (upstream pin, via the flake) | pass, CBMC 6.11.0 (Homebrew) |
| hol_x86_64 | AVX2 assembly functionally correct and memory safe at object-code level, 19 proofs | pass, 518 min | not runnable on this host |
| hol_aarch64 | Neon assembly, same properties, 22 proofs | not runnable on this host | pass, 558 min |
| ct | valgrind 3.26.0 with `--variable-latency-errors=yes` over the functional tests, C and AVX2 builds, ML-DSA-44/65/87 | pass | not runnable (no valgrind on macOS arm64) |

The Linux CBMC run is the one of record, since it uses the toolchain upstream pins. The macOS CBMC
run is a second run with a newer CBMC; it reports the same 210 proofs successful.

## Runs

### Linux x86_64, 2026-10-22

- Host: Linux 6.8.0-142-lowlatency x86_64, 48 cores, 503 GB
- Tools: nix flake at the pin for every stage (CBMC 6.10.0, litani 1.29.0, z3 4.15.3, bitwuzla 0.9.0,
  HOL Light and s2n-bignum as pinned by `nix/`, valgrind 3.26.0 with the variable-latency patch)
- Stages: conformance, cbmc, hol_x86_64, ct. Verdict `INCOMPLETE` by design (hol_aarch64 not runnable).
- Log: `mldsa-native-834a90d5e846-20261022T093450Z.log`, sha256
  `9259ade9d1e7f1e32b9531601b09aae3cf297825f15f1ca60c667fe252434ebb`
- CBMC results: `verification/cbmc-mldsa65-v2.0.0-linux-x86_64-20261022.json`, sha256
  `cf814726781e689cee17c32541a6d4de4343482eb5f5a552204440bd886daa98`

### macOS arm64, 2026-10-23

- Host: Darwin 27.0.0 arm64, 12 cores, 64 GB
- Tools: nix flake for conformance and HOL Light; Homebrew CBMC 6.11.0, litani 1.29.0, z3 and
  bitwuzla for the CBMC stage (the flake's cbmc shell does not build on macOS)
- Stages: conformance, cbmc, hol_aarch64 in one run. Verdict `INCOMPLETE` by design (hol_x86_64
  and ct not runnable, CBMC not the pinned version).
- Log: `mldsa-native-834a90d5e846-20261023T080427Z.log`, sha256
  `c389c19d2737b29f764cd8010e639cfa544959c1467f2dda95a224de454bf99c`
- CBMC results: `verification/cbmc-mldsa65-v2.0.0-darwin-arm64-20261023.json`, sha256
  `ad73ee29e045ffd83c45a40af46a0856b80e3c7210f5f324c9609eed98689c18` (210 of 210 successful)

An earlier pair of macOS runs on 2026-10-22 reached the same results; they were superseded by
this single run so that one log covers the host.

## Published logs

The full logs are too large to commit. Redacted copies (home directory paths shortened, nothing
else changed) are gzipped and attached as assets to the
[v0.2.0 release](https://github.com/MystenLabs/mysten-mldsa-native-rs/releases/tag/v0.2.0), the
release that first pinned this commit. The hashes are of the gzipped files; check them after
download, since release assets can be replaced and this file cannot without a commit.

| File | sha256 |
|---|---|
| `mldsa-native-v2.0.0-linux-x86_64-conformance-cbmc-hol_x86_64-ct.log.gz` | `d3be74d1d63070e383956583d6fdf173a11a89eebb688d6fecafd816161b94c8` |
| `mldsa-native-v2.0.0-darwin-arm64-conformance-cbmc-hol_aarch64.log.gz` | `330c0028c4c4a38414cf6aae807e95366a4f165d5d78640e54c743931f8d02eb` |

```
gh release download v0.2.0 -R MystenLabs/mysten-mldsa-native-rs -p '*.log.gz'
shasum -a 256 *.log.gz
```

## Scope

This reproduces upstream's proofs and tests on the commit in our dependency tree. The Rust wrapper,
its `MLD_CONFIG_*` choices in `build.rs`, and everything above it are outside that scope. They get
functional testing only, through this crate's test suite and the fastcrypto-pq vectors, which is
not a formal guarantee. `SOUNDNESS.md` in upstream lists what the proofs assume. Two residual gaps at this tag: the constant-time property of the `rej_uniform_eta{2,4}`
samplers is tested by valgrind but not proved (upstream's proof landed after v2.0.0), and the
x86_64 eta samplers on upstream `main` differ from v2.0.0 by one `vzeroupper`.

## Re-running

```
scripts/verify-upstream.sh                                   # every stage this host can run
STAGES="conformance cbmc" scripts/verify-upstream.sh         # the fast pair
```

The pin defaults to the `deps/mldsa-native` commit recorded in the checkout the script runs from, so
a re-pin moves it; overriding `PIN` to another commit makes the verdict `INCOMPLETE`. Run it on one
x86_64 Linux host and one arm64 host; together they reach every stage. Do not edit the script while
a run is in progress: bash reads it incrementally.
