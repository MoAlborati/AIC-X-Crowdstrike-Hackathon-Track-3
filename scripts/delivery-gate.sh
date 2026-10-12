#!/usr/bin/env bash
# delivery-gate.sh — the final delivery gate as ONE command, on Linux/WSL and on stock macOS.
#
#   "Delivery gate 15:15–15:45 on main + Catherine's Mac"
#
# Runs, in order, logging each step to .eval/delivery-<UTC timestamp>/:
#   1. scripts/eval.sh doctor
#   2. scripts/eval.sh up
#   3. scripts/eval.sh all
#   4. demo/run-demo.sh --check-script (only if run-demo.sh supports it), then
#      demo/run-demo.sh --auto  x5 (each run's exit code recorded)
#   5. scripts/egress-demo.sh both, on a unique EGRESS_PROJECT / EGRESS_NET (never collides with a
#      stack someone else left up)
#   6. scripts/eval.sh track3a (only if eval.sh has that target)
# then prints a summary table (step | result | duration | log), appends a dated entry with machine info
# and the git SHA to demo/REHEARSAL.md's delivery-gate log, and exits 1 if any step failed.
#
# Nothing is skipped silently: a missing component prints "MISSING: <x>". A missing REQUIRED script
# (eval.sh, run-demo.sh, egress-demo.sh) is a FAIL; a missing OPTIONAL one (--check-script, track3a) is
# reported as MISSING and fails only under DG_STRICT=1.
#
# bash 3.2-safe (macOS /bin/bash): no mapfile, no associative arrays, no ${v,,}, empty arrays guarded
# under set -u. Uses scripts/lib/portable.sh (run_with_timeout) when present, else a local fallback.
#
# Env knobs:
#   DG_STRICT=1              MISSING optional components count as FAIL
#   DG_DEMO_RUNS=5           number of demo/run-demo.sh --auto replays
#   DG_DEMO_ARGS="--no-dvaa" extra args for each replay (default --no-dvaa: step 2 already brought the
#                            fleet up, and the replay must not stop the shared fleet on teardown)
#   DG_STEP_TIMEOUT=1800     per-step wall clock cap in seconds (a step that hits it is a FAIL)
#   DG_HOST_LABEL            free-text machine label for the REHEARSAL entry (e.g. "Catherine's Mac")
#   DG_NO_RECORD=1           do not append to demo/REHEARSAL.md
#   EGRESS_PROJECT/EGRESS_NET override the generated unique values
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 2

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$REPO/.eval/delivery-$TS"
mkdir -p "$OUT" || { echo "FAIL: cannot create $OUT"; exit 2; }
REHEARSAL="$REPO/demo/REHEARSAL.md"
EVAL="$REPO/scripts/eval.sh"
DEMO="$REPO/demo/run-demo.sh"
EGRESS="$REPO/scripts/egress-demo.sh"
STRICT="${DG_STRICT:-0}"
DEMO_RUNS="${DG_DEMO_RUNS:-5}"
DEMO_ARGS="${DG_DEMO_ARGS---no-dvaa}"
STEP_TIMEOUT="${DG_STEP_TIMEOUT:-1800}"

# ------------------------------------------------------------------------------- timeout shim
if [ -f "$REPO/scripts/lib/portable.sh" ]; then
  # shellcheck source=/dev/null
  . "$REPO/scripts/lib/portable.sh"
  TIMEOUT_IMPL="scripts/lib/portable.sh"
fi
if ! type run_with_timeout >/dev/null 2>&1; then
  # Local fallback (portable.sh not on this branch yet): GNU timeout, Homebrew gtimeout, perl, or none.
  run_with_timeout() { # secs cmd...
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then timeout --kill-after=10 "$secs" "$@"; return $?; fi
    if command -v gtimeout >/dev/null 2>&1; then gtimeout --kill-after=10 "$secs" "$@"; return $?; fi
    if command -v perl >/dev/null 2>&1; then
      perl -e 'my $s=shift; my $p=fork(); die "fork: $!" unless defined $p;
        if(!$p){ setpgrp(0,0); exec @ARGV or exit 127 }
        local $SIG{ALRM}=sub{ kill "TERM",-$p; sleep 10; kill "KILL",-$p; exit 124 };
        alarm $s; waitpid($p,0); exit($? & 127 ? 128+($? & 127) : $? >> 8)' "$secs" "$@"
      return $?
    fi
    "$@"
  }
  TIMEOUT_IMPL="local fallback"
fi

# ------------------------------------------------------------------------------- result table
ROW_STEP=(); ROW_RES=(); ROW_DUR=(); ROW_LOG=()
FAILED=0
c_red=""; c_grn=""; c_yel=""; c_off=""
if [ -t 1 ]; then c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_off=$'\033[0m'; fi

add_row() { # step result duration log
  ROW_STEP[${#ROW_STEP[@]}]="$1"; ROW_RES[${#ROW_RES[@]}]="$2"
  ROW_DUR[${#ROW_DUR[@]}]="$3"; ROW_LOG[${#ROW_LOG[@]}]="$4"
}
rel() { case "$1" in "$REPO"/*) echo "${1#"$REPO"/}" ;; *) echo "$1" ;; esac; }

missing() { # name required(1|0) [note]
  echo "${c_yel}MISSING: $1${3:+ — $3}${c_off}"
  if [ "$2" = 1 ] || [ "$STRICT" = 1 ]; then add_row "$1" "FAIL (MISSING)" "-" "-"; FAILED=1
  else add_row "$1" "MISSING" "-" "-"; fi
}

# run_step NAME LOGFILE CMD...  — runs CMD with output to LOGFILE, records PASS/FAIL + duration.
run_step() {
  local name="$1" log="$2" t0 t1 rc res; shift 2
  printf '%s>> %s%s\n' "$c_yel" "$name" "$c_off"
  t0="$(date +%s)"
  { echo "# $name"; echo "# cmd: $*"; echo "# start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; } > "$log"
  run_with_timeout "$STEP_TIMEOUT" "$@" >> "$log" 2>&1 < /dev/null; rc=$?
  t1="$(date +%s)"
  echo "# exit: $rc" >> "$log"
  if [ "$rc" = 0 ]; then res="PASS"
  elif [ "$rc" = 124 ]; then res="FAIL (timeout ${STEP_TIMEOUT}s)"; FAILED=1
  else res="FAIL (exit $rc)"; FAILED=1; fi
  add_row "$name" "$res" "$((t1 - t0))s" "$(rel "$log")"
  if [ "$rc" = 0 ]; then printf '   %sPASS%s (%ss)\n' "$c_grn" "$c_off" "$((t1 - t0))"
  else
    printf '   %s%s%s (%ss) — last lines of %s:\n' "$c_red" "$res" "$c_off" "$((t1 - t0))" "$(rel "$log")"
    tail -n 15 "$log" | sed 's/^/      | /'
  fi
  return "$rc"
}

has_eval_target() { [ -f "$EVAL" ] && grep -Eq "^[[:space:]]*$1\)" "$EVAL"; }

# ------------------------------------------------------------------------------- machine info
SHA="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
BRANCH="$(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
DIRTY=""; [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no 2>/dev/null)" ] && DIRTY=" (dirty)"
UNAME="$(uname -sm)"
NODEV="$(node --version 2>/dev/null || echo 'not found')"
DCTX="$(docker context show 2>/dev/null || echo 'unknown')"
HOST_LABEL="${DG_HOST_LABEL:-$(hostname 2>/dev/null || echo unknown)}"
{
  echo "timestamp: $TS"; echo "sha: $SHA$DIRTY"; echo "branch: $BRANCH"; echo "uname: $UNAME"
  echo "bash: $BASH_VERSION"; echo "node: $NODEV"; echo "docker context: $DCTX"; echo "host: $HOST_LABEL"
  echo "timeout impl: $TIMEOUT_IMPL"
} > "$OUT/machine.txt"
echo "delivery gate @ ${SHA:0:12}$DIRTY ($BRANCH) on $UNAME · bash $BASH_VERSION · node $NODEV · docker $DCTX"
echo "logs: $(rel "$OUT")/"

# ------------------------------------------------------------------------------- 1-3: eval.sh
if [ -f "$EVAL" ]; then
  for t in doctor up all; do
    if has_eval_target "$t"; then run_step "eval.sh $t" "$OUT/eval-$t.log" bash "$EVAL" "$t"
    else missing "scripts/eval.sh $t" 1; fi
  done
else
  missing "scripts/eval.sh" 1
fi

# ------------------------------------------------------------------------------- 4: demo replays
if [ -f "$DEMO" ]; then
  if grep -q -- '--check-script' "$DEMO"; then
    run_step "run-demo.sh --check-script" "$OUT/demo-check-script.log" bash "$DEMO" --check-script
  else
    missing "run-demo.sh --check-script" 0 "lands with PR #50"
  fi
  i=1; DEMO_OK=0
  while [ "$i" -le "$DEMO_RUNS" ]; do
    # shellcheck disable=SC2086  # DEMO_ARGS is a deliberately word-split flag list
    if run_step "run-demo.sh --auto #$i" "$OUT/demo-auto-$i.log" bash "$DEMO" --auto $DEMO_ARGS; then
      DEMO_OK=$((DEMO_OK + 1))
    fi
    i=$((i + 1))
  done
  echo "   demo replays clean: $DEMO_OK/$DEMO_RUNS"
else
  missing "demo/run-demo.sh" 1
fi

# ------------------------------------------------------------------------------- 5: egress
if [ -f "$EGRESS" ]; then
  if [ -z "${EGRESS_NET:-}" ]; then
    # Pick a 10.231.N.0/24 not already used by any docker network (default compose uses 10.231.12).
    used="$(docker network inspect $(docker network ls -q 2>/dev/null) \
              -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | tr ' ' '\n')"
    n=$(( ($$ % 150) + 100 )); tries=0
    while printf '%s\n' "$used" | grep -q "^10\.231\.$n\." && [ "$tries" -lt 150 ]; do
      n=$(( n + 1 )); [ "$n" -gt 250 ] && n=100; tries=$((tries + 1))
    done
    EGRESS_NET="10.231.$n"
  fi
  export EGRESS_NET
  export EGRESS_PROJECT="${EGRESS_PROJECT:-sentinel-egress-dg-$(echo "$TS" | tr 'A-Z' 'a-z')-$$}"
  export EGRESS_LOG_DIR="${EGRESS_LOG_DIR:-$OUT/egress-logs}"
  echo "   egress: project $EGRESS_PROJECT, net $EGRESS_NET.0/24"
  run_step "egress-demo.sh both" "$OUT/egress-both.log" bash "$EGRESS" both
else
  missing "scripts/egress-demo.sh" 1
fi

# ------------------------------------------------------------------------------- 6: track3a
if has_eval_target track3a; then
  run_step "eval.sh track3a" "$OUT/eval-track3a.log" bash "$EVAL" track3a
else
  missing "eval.sh track3a" 0 "lands with PR #70"
fi

# ------------------------------------------------------------------------------- summary
VERDICT="PASS"; [ "$FAILED" = 1 ] && VERDICT="FAIL"
TABLE="$OUT/summary.md"
{
  echo "| Step | Result | Duration | Log |"
  echo "|---|---|---|---|"
  i=0
  while [ "$i" -lt "${#ROW_STEP[@]}" ]; do
    echo "| ${ROW_STEP[$i]} | ${ROW_RES[$i]} | ${ROW_DUR[$i]} | ${ROW_LOG[$i]} |"
    i=$((i + 1))
  done
} > "$TABLE"

echo
echo "== delivery gate summary =="
printf '%-30s %-22s %-9s %s\n' "STEP" "RESULT" "DURATION" "LOG"
i=0
while [ "$i" -lt "${#ROW_STEP[@]}" ]; do
  case "${ROW_RES[$i]}" in PASS) c="$c_grn" ;; MISSING) c="$c_yel" ;; *) c="$c_red" ;; esac
  printf '%-30s %s%-22s%s %-9s %s\n' "${ROW_STEP[$i]}" "$c" "${ROW_RES[$i]}" "$c_off" "${ROW_DUR[$i]}" "${ROW_LOG[$i]}"
  i=$((i + 1))
done
echo
echo "VERDICT: $VERDICT  (sha ${SHA:0:12}$DIRTY, logs $(rel "$OUT")/)"

# ------------------------------------------------------------------------------- REHEARSAL entry
MARK_END='<!-- delivery-gate-log:end -->'
if [ "${DG_NO_RECORD:-0}" = 1 ]; then
  echo "DG_NO_RECORD=1: not appending to demo/REHEARSAL.md"
elif [ -f "$REHEARSAL" ] && grep -qF "$MARK_END" "$REHEARSAL"; then
  ENTRY="$OUT/rehearsal-entry.md"
  {
    echo "#### $(date -u +%Y-%m-%dT%H:%MZ) — $VERDICT — \`${SHA:0:12}\`$DIRTY on $HOST_LABEL"
    echo "- Machine: \`$UNAME\` · bash $BASH_VERSION · node $NODEV · docker context \`$DCTX\` · branch \`$BRANCH\`"
    echo "- Logs: \`$(rel "$OUT")/\`"
    echo
    cat "$TABLE"
    echo
  } > "$ENTRY"
  # Insert the entry just above the end marker (awk, not sed -i: BSD and GNU sed -i differ).
  awk -v f="$ENTRY" -v m="$MARK_END" '$0 == m { while ((getline l < f) > 0) print l } { print }' \
    "$REHEARSAL" > "$OUT/REHEARSAL.md.new" && cat "$OUT/REHEARSAL.md.new" > "$REHEARSAL" \
    && echo "recorded in demo/REHEARSAL.md (delivery-gate log)"
else
  echo "${c_yel}MISSING: delivery-gate log marker in demo/REHEARSAL.md — entry not recorded (see $(rel "$OUT")/summary.md)${c_off}"
  FAILED=1
fi

[ "$FAILED" = 1 ] && exit 1
exit 0
