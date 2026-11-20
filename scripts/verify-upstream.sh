#!/bin/bash
# Re-run upstream's CI jobs (conformance, CBMC, HOL-Light, CT) on the pinned mldsa-native commit.
#
#   ./verify-upstream.sh                      # every stage this host can run
#   STAGES="conformance cbmc" ./verify-upstream.sh
#
# The pin defaults to the deps/mldsa-native commit recorded in this crate checkout, so a re-pin
# moves it without editing this file; a PIN override that differs makes the verdict INCOMPLETE.
# The checkout is verified first: pin, origin, clean tree, submodules. Exit 0 PASS, 1 FAIL,
# 3 INCOMPLETE (a REQUIRED stage could not run here; a Linux and a Mac run together cover all).
# Tools come from the flake; on macOS the cbmc stage uses Homebrew (cbmc litani ninja z3 bitwuzla).
set -u
die() { echo "error: $*" >&2; exit 2; }

UPSTREAM=https://github.com/pq-code-package/mldsa-native.git
CRATE=$(cd "$(dirname "$0")/.." && pwd)
GITLINK=$(git -C "$CRATE" rev-parse --verify -q HEAD:deps/mldsa-native 2>/dev/null || true)
PIN=${PIN:-$GITLINK}
[ -n "$PIN" ] || die "no PIN given and $CRATE has no deps/mldsa-native gitlink"
PARAM=${PARAM:-65}                                      # 44 | 65 | 87 | ALL
WORK=${WORK:-$HOME/pq-verify/mldsa-native}
LOGDIR=${LOGDIR:-$HOME/pq-verify/logs}
STAGES=${STAGES:-conformance cbmc hol_aarch64 hol_x86_64 ct}
REQUIRED=${REQUIRED:-conformance cbmc hol_aarch64 hol_x86_64 ct}
JOBS=${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || nproc)}
# Upstream's pin; a different host cbmc makes the verdict INCOMPLETE.
CBMC_EXPECTED=6.10.0

# A fresh nix install is only on PATH in new shells.
if ! command -v nix >/dev/null && [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
  . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
fi
NIX=${NIX:-$(command -v nix >/dev/null && echo nix || echo none)}
# The flake's cbmc shell does not build on macOS (z3's Python check aborts), so use host tools there.
HOST_STAGES=${HOST_STAGES:-$([ "$(uname -s)" = Darwin ] && echo cbmc)}
HOST_ARCH=$(uname -m | sed 's/arm64/aarch64/')

# These are interpolated into shell commands; accept only the expected shapes.
case $PARAM in 44|65|87|ALL) ;; *) die "PARAM must be 44, 65, 87 or ALL, got '$PARAM'" ;; esac
case $JOBS in ''|*[!0-9]*|0) die "JOBS must be a positive integer, got '$JOBS'" ;; esac
case $PIN in *[!0-9a-f]*|'') die "PIN must be a full lowercase commit hash" ;; esac
[ ${#PIN} -eq 40 ] || die "PIN must be 40 hex characters"
for v in WORK LOGDIR; do
  case ${!v} in /*) ;; *) die "$v must be an absolute path" ;; esac
  case ${!v} in *[\'\"\$\`\\\;\&\|\<\>\(\)\ ]*) die "$v must not contain shell metacharacters or spaces" ;; esac
done
for s in $STAGES $REQUIRED; do
  case $s in conformance|cbmc|cbmc_reduce_ram|hol_aarch64|hol_x86_64|ct) ;; *) die "unknown stage '$s'" ;; esac
done
case $NIX in nix|none) ;; *) die "NIX must be 'nix' or 'none'" ;; esac
PIN_NOTE=""
[ -z "$GITLINK" ] || [ "$PIN" = "$GITLINK" ] || PIN_NOTE="pin is not the crate's submodule commit ${GITLINK:0:12}"

mkdir -p "$LOGDIR" "$(dirname "$WORK")" || die "cannot create $LOGDIR or $(dirname "$WORK")"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG=$LOGDIR/mldsa-native-${PIN:0:12}-$STAMP.log
exec > >(tee -a "$LOG") 2>&1

declare STATUS_NAMES="" ; STATUS_LINES=""
record() {  # name outcome [detail]
  local name=$1 outcome=$2 detail=${3:-}
  STATUS_NAMES="$STATUS_NAMES $name=$outcome"
  STATUS_LINES="$STATUS_LINES$(printf "%-16s %-8s %s" "$name" "$outcome" "$detail")\n"
  echo "# $name: $outcome $detail"
}
banner() { echo; echo "################ $* ################"; echo "# $(date -u +%FT%TZ)"; }

run_stage() {  # name, nix shell, command string (built only from validated values above)
  local name=$1 shell=$2; shift 2
  local t0=$SECONDS rc
  if [ "$NIX" = none ] || [[ " $HOST_STAGES " == *" $name "* ]]; then
    case $name in hol_*|ct)
      banner "$name"
      record "$name" skipped "needs the nix shell .#$shell, no nix on this host"
      return ;;
    esac
    banner "$name  (host tools)"
    local missing=""
    # Proofs pick their own solver; some need z3 or bitwuzla.
    for t in cbmc litani cbmc-viewer ninja z3 bitwuzla; do
      printf "# %-12s %s\n" "$t" "$(command -v "$t" || echo MISSING)"
      command -v "$t" >/dev/null || missing="$missing $t"
    done
    if [ "$name" = cbmc ] || [ "$name" = cbmc_reduce_ram ]; then
      [ -z "$missing" ] || { record "$name" fail "missing host tools:$missing (brew install cbmc litani ninja z3 bitwuzla; cbmc-viewer from pip)"; return; }
    fi
    (cd "$WORK" && bash -c "$*")
    rc=$?
  else
    banner "$name  (nix develop .#$shell)"
    (cd "$WORK" && "$NIX" develop ".#$shell" --accept-flake-config --command bash -c "$*")
    rc=$?
  fi
  if [ "$rc" -eq 0 ]; then record "$name" pass "$(( (SECONDS - t0) / 60 ))min"
  else record "$name" fail "rc=$rc after $(( (SECONDS - t0) / 60 ))min"; fi
}

banner "run"
echo "log      $LOG"
echo "pin      $PIN"
echo "crate    $CRATE, submodule ${GITLINK:-none}"
[ -z "$PIN_NOTE" ] || echo "note     $PIN_NOTE"
echo "param    $PARAM"
echo "stages   $STAGES"
echo "required $REQUIRED"
echo "host     $(uname -srm), $JOBS cpus, $(( $(sysctl -n hw.memsize 2>/dev/null || grep MemTotal /proc/meminfo | awk '{print $2*1024}') / 1073741824 )) GB"
TOOL_NOTE=""
if [ "$NIX" = none ] || [[ " $HOST_STAGES " == *" cbmc "* ]]; then
  echo "cbmc     host tools: $(cbmc --version 2>/dev/null || echo MISSING); litani $(litani --version 2>/dev/null || echo MISSING)"
  if ! cbmc --version 2>/dev/null | grep -q "^$CBMC_EXPECTED"; then
    TOOL_NOTE="host cbmc is not the upstream pin $CBMC_EXPECTED"
    echo "note     $TOOL_NOTE"
  fi
fi
[ "$NIX" = none ] && echo "nix      none; hol_* and ct cannot run here" || "$NIX" --version

# === Source identity ===
banner "pin"
if [ ! -d "$WORK/.git" ]; then
  git clone --quiet "$UPSTREAM" "$WORK" || die "clone failed"
fi
origin=$(git -C "$WORK" remote get-url origin)
[ "$origin" = "$UPSTREAM" ] || die "$WORK has origin '$origin', expected $UPSTREAM"
git -C "$WORK" fetch --quiet --tags origin || die "fetch failed"
git -C "$WORK" checkout --quiet --detach "$PIN" || die "cannot check out $PIN"
git -C "$WORK" submodule update --init --recursive --quiet || die "submodule update failed"
[ "$(git -C "$WORK" rev-parse HEAD)" = "$PIN" ] || die "HEAD is not the pin"
dirty=$(git -C "$WORK" status --porcelain --untracked-files=all)
[ -z "$dirty" ] || { echo "$dirty" | head -20; die "source tree is dirty; remove $WORK and rerun"; }
git -C "$WORK" submodule foreach --recursive --quiet '
  test -z "$(git status --porcelain --untracked-files=all)" || { echo "dirty submodule $name"; exit 1; }' \
  || die "a submodule is dirty; remove $WORK and rerun"
# + or - prefix means a submodule is not at its recorded commit.
mismatch=$(git -C "$WORK" submodule status --recursive | grep -v '^ ' || true)
[ -z "$mismatch" ] || { echo "$mismatch"; die "a submodule is not at its recorded commit"; }
echo "HEAD     $PIN"
echo "describe $(git -C "$WORK" describe --tags --always)"
echo "date     $(git -C "$WORK" log -1 --format=%cI)"
echo "tree     clean, submodules at recorded commits"

for stage in $STAGES; do
  case $stage in
    cbmc)
      run_stage cbmc cbmc "cbmc --version; \
        ./scripts/tests cbmc --mldsa-parameter-set $PARAM -j $JOBS \
          --per-proof-timeout 1800 --output-result-json $LOGDIR/cbmc-$PARAM-$STAMP.json"
      ;;
    cbmc_reduce_ram)
      run_stage cbmc_reduce_ram cbmc "./scripts/tests cbmc --mldsa-parameter-set $PARAM -j $JOBS \
          --per-proof-timeout 1800 --reduce-ram --output-result-json $LOGDIR/cbmc-$PARAM-reduce-ram-$STAMP.json"
      ;;
    hol_aarch64|hol_x86_64)
      # v2.0.0 proves the host's own arch only.
      arch=${stage#hol_}
      if [ "$arch" != "$HOST_ARCH" ]; then
        banner "$stage"
        record "$stage" skipped "v2.0.0 proves the host arch only; this host is $HOST_ARCH"
      else
        run_stage "$stage" hol_light "./scripts/tests hol_light -l && ./scripts/tests hol_light -j $JOBS -v"
      fi
      ;;
    conformance)
      run_stage conformance ci "./scripts/tests func -j $JOBS && \
        ./scripts/tests kat -j $JOBS && \
        ./scripts/tests acvp && \
        ./scripts/tests wycheproof"
      ;;
    ct)
      # Same flags as upstream's ct-test action. Linux only.
      run_stage ct valgrind-varlat_gcc14 "valgrind --version; MK_COMPILER_SUPPORTS_SHA3=0 \
        ./scripts/tests func -j $JOBS \
          --exec-wrapper='valgrind --vex-guest-max-insns=55 --error-exitcode=1 --variable-latency-errors=yes' \
          --cflags='-DMLD_CONFIG_CT_TESTING_ENABLED -DNTESTS=5'"
      ;;
  esac
done

# === Verdict ===
banner "summary"
echo "pin      $PIN ($(git -C "$WORK" describe --tags --always))"
printf "%b" "$STATUS_LINES"
verdict=PASS; code=0
case $STATUS_NAMES in *=fail*) verdict=FAIL; code=1 ;; esac
if [ "$verdict" = PASS ]; then
  for r in $REQUIRED; do
    case $STATUS_NAMES in *" $r=pass"*) ;; *) verdict=INCOMPLETE; code=3; echo "missing  $r did not pass on this host" ;; esac
  done
  [ -z "$TOOL_NOTE" ] || { verdict=INCOMPLETE; code=3; echo "missing  $TOOL_NOTE"; }
  [ -z "$PIN_NOTE" ] || { verdict=INCOMPLETE; code=3; echo "missing  $PIN_NOTE"; }
fi
echo "verdict  $verdict"
echo "log      $LOG"
exit $code
