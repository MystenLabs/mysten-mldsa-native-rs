# Contributing to This Project

Thanks for considering making a contribution to mysten-mldsa-native-rs. Before you get
started, please take a moment to read these guidelines.

## Important Note

We appreciate contributions, but **simple typo fixes (e.g., minor spelling errors,
punctuation changes, or trivial rewording) will be ignored** unless they significantly
improve clarity or fix a critical issue. If you are unsure whether your change is
substantial enough, consider opening an issue first to discuss it.

## Reporting Issues

Found a bug? Please check the existing issues before opening a new one, and provide as
much detail as possible: steps to reproduce, expected behavior, and actual behavior.

**Security vulnerabilities must not be reported as public issues.** See
[SECURITY.md](./SECURITY.md) for how to report them privately.

## What This Crate Is Careful About

This wrapper is written for use in consensus-critical software, and some of its
properties are load-bearing in ways an ordinary library's are not:

- **Wire-format stability.** The known-answer tests pin public key and signature bytes
  against independent implementations of FIPS 204. A change that moves any of those
  bytes is not a refactor; do not fix a failing KAT by updating its expected values
  without raising it explicitly in your pull request.
- **The vendored C is consumed exactly as pinned.** `deps/mldsa-native` is never
  patched locally; all configuration happens through `MLD_CONFIG_*` defines in
  `build.rs`. A submodule re-pin must update `PROVENANCE.md` in the same pull request
  (CI checks that they match) and keep every KAT passing byte for byte.
- **No vector code outside the probe-gated assembly.** The build never passes
  architecture flags such as `-mavx2`, and CI checks the compiled C for stray vector
  instructions. Do not add such flags, in the build or in `CFLAGS`.

If your change touches any of these areas, please open an issue first.

## Proposing Code Changes

Fork the repository and create a new branch for your changes, based on the latest
`main`. Follow the existing code structure and comment style, and write meaningful
commit messages.

If your change is significant, please open an issue first to discuss it.

## Submitting a Pull Request

Ensure your changes are well-tested and run what CI runs before pushing:

```bash
cargo test --all-features
cargo fmt --all --check
cargo xclippy -D warnings   # project clippy alias, see .cargo/config.toml
scripts/license_check.sh
cargo deny check            # needs cargo-deny installed
```

The full CI matrix additionally tests on Linux, macOS, and Windows, cross-compiles the
remaining supported targets, and runs the suite at release optimization and under
AddressSanitizer.

Provide a clear description of your changes in the pull request, reference any relevant
issue numbers, and be responsive to feedback from maintainers.

## Documentation

Crate documentation is rustdoc, published to GitHub Pages at
<https://mystenlabs.github.io/mysten-mldsa-native-rs/docs/> on every push to `main`.
Documentation examples compile and run as doctests in CI, so keep them working.

## License

By contributing, you agree that your contributions will be licensed under the same
license as this project (Apache-2.0).

Thank you for contributing!
