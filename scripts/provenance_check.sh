#!/bin/bash
# Checks that the vendored mldsa-native is what PROVENANCE.md says it is:
#
# 1. .gitmodules points the submodule at upstream.
# 2. The gitlink, the commit this repository pins, is the documented one.
# 3. Upstream's documented release tag resolves to that commit.
# 4. The checked-out mldsa/ directory, the only part this crate compiles and packages,
#    has no local changes and has the documented git tree hash.
#
# Without it, a pull request that moved the pin and edited PROVENANCE.md to match would
# pass every mechanical check.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

UPSTREAM=https://github.com/pq-code-package/mldsa-native.git
SUBMODULE=deps/mldsa-native

fail() { echo "provenance check failed: $*" >&2; exit 1; }

# The value in backticks on the PROVENANCE.md bullet "- **<label>:** `<value>`".
documented() {
  local value
  value=$(sed -n "s/^- \*\*$1:\*\* \`\([^\`]*\)\`.*/\1/p" PROVENANCE.md)
  [ -n "$value" ] && [ "$(printf '%s\n' "$value" | wc -l)" -eq 1 ] ||
    fail "PROVENANCE.md must have exactly one '- **$1:** \`...\`' line"
  printf '%s' "$value"
}

commit=$(documented "Pinned commit")
tag=$(documented "Upstream tag")
tree=$(documented "Vendored tree")
[[ $commit =~ ^[0-9a-f]{40}$ ]] || fail "documented commit '$commit' is not a full hash"
[[ $tree =~ ^[0-9a-f]{40}$ ]] || fail "documented tree '$tree' is not a full hash"
[[ $tag =~ ^v[0-9A-Za-z._-]+$ ]] || fail "documented tag '$tag' is not a release tag"

url=$(git config --file .gitmodules "submodule.$SUBMODULE.url")
[ "$url" = "$UPSTREAM" ] || fail ".gitmodules points at '$url', expected $UPSTREAM"

gitlink=$(git ls-tree HEAD "$SUBMODULE" | awk '{print $3}')
[ "$gitlink" = "$commit" ] || fail "gitlink is ${gitlink:-missing}, PROVENANCE.md documents $commit"

# An annotated tag lists its commit on the peeled "^{}" line; a lightweight tag has only
# the plain line.
refs=$(git ls-remote "$UPSTREAM" "refs/tags/$tag" "refs/tags/$tag^{}")
tagged=$(printf '%s\n' "$refs" | awk -v peeled="refs/tags/$tag^{}" \
  '$2 == peeled { p = $1 } $2 != peeled { s = $1 } END { print (p != "" ? p : s) }')
[ "$tagged" = "$commit" ] || fail "upstream's $tag is ${tagged:-missing}, PROVENANCE.md documents $commit"

[ -e "$SUBMODULE/.git" ] || fail "$SUBMODULE is not checked out (git submodule update --init)"
head=$(git -C "$SUBMODULE" rev-parse HEAD)
[ "$head" = "$commit" ] || fail "$SUBMODULE is checked out at $head, not the pinned $commit"
changes=$(git -C "$SUBMODULE" status --porcelain --untracked-files=all -- mldsa)
[ -z "$changes" ] || fail "$SUBMODULE/mldsa has local changes:
$changes"
actual=$(git -C "$SUBMODULE" rev-parse HEAD:mldsa)
[ "$actual" = "$tree" ] || fail "mldsa/ has tree $actual, PROVENANCE.md documents $tree"

echo "provenance check passed: $tag = $commit, mldsa/ tree $tree"
