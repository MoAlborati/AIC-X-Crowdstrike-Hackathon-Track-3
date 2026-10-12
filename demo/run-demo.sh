#!/usr/bin/env bash
# demo/run-demo.sh — deterministic driver for the SentinelProxy demo (ticket T9).
#
# Drives the beats of demo/SCRIPT.md on THIS machine, in order, from the committed
# captures/ fixtures. Nothing here makes a live LLM/API call inside the demo window
# (GOAL.md ground rule): the exploit, the AIM-twin verdict and the scoring table all
# replay deterministically from captures/ and the merged components.
#
# This is a DEFENSIVE demo for an authorized, sanctioned CrowdStrike x Santa Clara
# University hackathon (Track 3). DVAA is the organizers' intentionally-vulnerable
# training sandbox, run only on localhost. We never attack any real system.
#
# Modes:
#   (default)   interactive — pause for Enter between beats ("press Enter to advance")
#   --auto      run every beat back-to-back with no prompts (for rehearsal / CI capture)
#
# Options:
#   --no-dvaa     skip the Docker DVAA bring-up (the replay demo does not need the
#                 live fleet; use this on a machine without Docker)
#   --keep-dvaa   leave the DVAA fleet running on teardown (default: stop what we started)
#   --no-teardown leave the dashboard running on exit (default: stop it)
#   -h | --help   this help
#
# Components not yet merged are wired behind a single registry below (see "WIRING
# REGISTRY"). Each prints "NOT YET MERGED: <component>" instead of being skipped
# silently; finalizing them at feature-freeze (14:30) is a one-place edit.
#
# Exit code: 0 if every beat that is wired-and-merged passed; 1 if any such beat
# failed. NOT-YET-MERGED beats are reported but do not fail the run before freeze.
set -uo pipefail

# --------------------------------------------------------------------------- paths
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# --------------------------------------------------------------------------- flags
AUTO=0; DO_DVAA=1; KEEP_DVAA=0; DO_TEARDOWN=1
for a in "$@"; do
  case "$a" in
    --auto) AUTO=1 ;;
    --no-dvaa) DO_DVAA=0 ;;
    --keep-dvaa) KEEP_DVAA=1 ;;
    --no-teardown) DO_TEARDOWN=0 ;;
    -h|--help) sed -n '2,/^set -uo/p' "$SELF" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

# ------------------------------------------------------------------------- styling
if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; B=$'\e[1m'; Z=$'\e[0m'
else R=; G=; Y=; C=; B=; Z=; fi
hdr()  { printf '\n%s============================================================%s\n%s%s%s\n' "$B" "$Z" "$B" "$*" "$Z"; }
say()  { printf '  %s"%s"%s\n' "$C" "$*" "$Z"; }           # a spoken line from SCRIPT.md
ok()   { printf '  %sPASS%s  %s\n' "$G" "$Z" "$*"; }
bad()  { printf '  %sFAIL%s  %s\n' "$R" "$Z" "$*"; }
warn() { printf '  %sWARN%s  %s\n' "$Y" "$Z" "$*"; }
nym()  { printf '  %sNOT YET MERGED%s  %s\n' "$Y" "$Z" "$*"; }
note() { printf '        %s\n' "$*"; }

# Beat result accumulator for the closing summary.
SUMMARY=()
record() { SUMMARY+=("$1|$2|$3"); }   # beat | RESULT | detail

# Run a shell command, echo it, indent its output, record PASS/FAIL. Returns the rc.
run_cmd() { # label  cmd...
  local label="$1"; shift
  printf '  %s$ %s%s\n' "$B" "$*" "$Z"
  ( "$@" ) 2>&1 | sed 's/^/    | /'
  local rc=${PIPESTATUS[0]}
  if [ "$rc" = 0 ]; then ok "$label"; record "$label" PASS "ok"
  else bad "$label (exit $rc)"; record "$label" FAIL "exit $rc"; fi
  return "$rc"
}

# Advance control: interactive pause, or straight through in --auto.
advance() {
  [ "$AUTO" = 1 ] && { printf '\n'; return 0; }
  if [ -t 0 ]; then
    local ans; printf '\n  %s--> press Enter to advance (q = quit)%s ' "$B" "$Z"
    read -r ans; [ "$ans" = q ] && { echo "  (quit)"; exit 0; }
  else
    printf '\n  (no TTY; advancing)\n'
  fi
}

# =================================================================================
# WIRING REGISTRY  ---  the ONE place to finalize at feature-freeze (14:30).
# Each not-yet-merged component is detected by the presence of its real entry point.
# When its PR merges to main, the file appears and the beat runs automatically; the
# only edit needed is to confirm/adjust the exact command in its *_cmd function.
# =================================================================================
EVAL="$REPO/scripts/eval.sh"                                   # merged: PR #20 (T11)
CAP_ATTACK="$REPO/captures/attack/aim-ab.demo.json"            # merged: T1
DASH_PORT="${EVAL_DASHBOARD_PORT:-9100}"                       # T5 dashboard (PR #11)

# T6 8KB-evasion fixtures (PR #10/#15) + T7 scoring output (PR #13). The scoring run is produced once
# and cached, so the evasion beat (Beat 3b) and the scoring beat (Beat 7) read the same results.
EVASION_MID=("$REPO/captures/variants/fixtures/evasion/eva-pos-middle-001.json" \
             "$REPO/captures/variants/fixtures/evasion/eva-bench-middle-001.json")
RESULTS_JSON="$REPO/.eval/score/results.json"
RESULTS_MD="$REPO/.eval/score/RESULTS.md"
SCORE_RAN=0
ensure_score() {   # run the T7 harness once; both Beat 3b and Beat 7 consume its output
  [ "$SCORE_RAN" = 1 ] && [ -f "$RESULTS_JSON" ] && return 0
  bash "$EVAL" score >/dev/null 2>&1; SCORE_RAN=1
  [ -f "$RESULTS_JSON" ]
}
evasion_proof_cmd() {   # DVAA's head/tail 8KB scan misses the mid-document injection; a full scan finds it
  jq -rc '{id, docLength:.baseline8kb.docLength, scanEdgeBytes:.baseline8kb.DETECTION_EDGE,
           injectionAtByte:.baseline8kb.injectionOffsetStart, inMiddleGap:.baseline8kb.inMiddleGap,
           evadesDvaaBaseline:.baseline8kb.evadesBaseline, fullScanFindsSignal:.baseline8kb.signalPresentOnFullScan}' \
    "${EVASION_MID[@]}"
}
t3_beats_baseline_cmd() {   # T3 catches exactly the mid-document cases DVAA's baseline misses
  jq -rc '.beatsBaseline | {evasionCasesBaselineMisses:.eligible,
           t3Caught:.byDetector.t3.beaten, cases:.byDetector.t3.cases}' "$RESULTS_JSON"
}

# T2 — request-side proxy block (PR #14/#21, MERGED). On stage we show the RECORDED block-mode proxy
# verdict log from the T8 contrast run — deterministic, no live proxy spin-up inside the 3-min window
# (GOAL.md ground rule). Live encore after the clock stops:
#   node sentinel/proxy/cli.mjs --config sentinel/config/sentinel.config.json   (then send a request through it)
PROXY_BLOCK_JSONL="$REPO/captures/contrast/runs/proxy-block.proxy.jsonl"
proxy_block_cmd() {
  jq -rc 'select((.action // "") | test("block")) | {request_id, action, target, latency_ms}' "$PROXY_BLOCK_JSONL"
}

# T12 — egress-guard block (spike PR #18, MERGED). On stage we show the RECORDED egress-guard denials
# (honeytoken + destination-not-allowlisted → deny). Live encore: spike/egress/run-spike.sh
EGRESS_BLOCK_JSONL="$REPO/spike/egress/evidence-block.jsonl"
egress_block_cmd() {
  jq -rc 'select(.action == "deny") | {kind, host, action, reasons}' "$EGRESS_BLOCK_JSONL"
}
# =================================================================================

STARTED_DASHBOARD=0; STARTED_DVAA=0
teardown() {
  hdr "Teardown"
  if [ "$STARTED_DASHBOARD" = 1 ] && [ "$DO_TEARDOWN" = 1 ]; then
    run_cmd "dashboard stopped" bash "$EVAL" dashboard-stop
  elif [ "$STARTED_DASHBOARD" = 1 ]; then
    warn "dashboard left running (--no-teardown): stop with 'scripts/eval.sh dashboard-stop'"
  fi
  if [ "$STARTED_DVAA" = 1 ] && [ "$KEEP_DVAA" = 0 ]; then
    run_cmd "DVAA fleet stopped" bash "$EVAL" down
  elif [ "$STARTED_DVAA" = 1 ]; then
    warn "DVAA fleet left running (--keep-dvaa)"
  fi
  print_summary
}
trap teardown EXIT

print_summary() {
  hdr "Summary"
  { echo "BEAT|RESULT|DETAIL"; printf '%s\n' "${SUMMARY[@]}"; } | \
  awk -F'|' '{printf "  %-34s %-16s %s\n", $1, $2, $3}'
  local fails
  fails=$(printf '%s\n' "${SUMMARY[@]}" | awk -F'|' '$2=="FAIL"' | wc -l | tr -d ' ')
  echo
  if [ "$fails" = 0 ]; then ok "demo run clean — no failing beats"
  else bad "$fails beat(s) FAILED — this is not a clean replay"; fi
}

# =================================================================================
# PRE-FLIGHT (not part of the 3-minute stage clock)
# =================================================================================
hdr "SentinelProxy demo  ·  mode=$([ "$AUTO" = 1 ] && echo AUTO || echo interactive)"
note "repo: $REPO"
note "SCRIPT: demo/SCRIPT.md    (deterministic replay from captures/)"

hdr "Preflight 1/3 — environment doctor (scripts/eval.sh doctor)"
if [ -x "$EVAL" ]; then
  # doctor is advisory: Docker/fleet-down are WARNs there. The replay demo runs from
  # captures regardless, so we surface the report but do not abort on a non-zero rc.
  bash "$EVAL" doctor 2>&1 | sed 's/^/  /' || warn "doctor reported issues (see above); continuing on deterministic captures"
  record "preflight: doctor" PASS "ran"
else
  nym "scripts/eval.sh (preflight doctor) — PR #20 / T11"
  record "preflight: doctor" "NOT YET MERGED" "scripts/eval.sh absent"
fi
advance

hdr "Preflight 2/3 — bring up DVAA (organizer sandbox, localhost only)"
if [ "$DO_DVAA" = 0 ]; then
  warn "DVAA bring-up skipped (--no-dvaa); demo replays from captures/ and does not need the live fleet"
  record "preflight: DVAA up" SKIP "--no-dvaa"
elif ! command -v docker >/dev/null 2>&1; then
  warn "Docker not available on this machine; skipping DVAA bring-up. Deterministic replay does not need it."
  record "preflight: DVAA up" SKIP "no docker"
elif curl -fsS --max-time 3 "http://127.0.0.1:9000/stats" >/dev/null 2>&1; then
  # Fleet already running (possibly shared with other agents) — leave it as-is, and do
  # NOT set STARTED_DVAA so teardown never stops a fleet this run did not start.
  ok "DVAA fleet already up on 127.0.0.1 (leaving it as-is; not ours to stop)"
  record "preflight: DVAA up" PASS "already up"
elif [ -x "$EVAL" ]; then
  if bash "$EVAL" up 2>&1 | sed 's/^/  /'; then
    STARTED_DVAA=1; ok "DVAA fleet up (127.0.0.1 only)"; record "preflight: DVAA up" PASS "fleet up (ours)"
  else
    warn "DVAA bring-up did not complete; continuing on deterministic captures"
    record "preflight: DVAA up" WARN "up failed; replay-only"
  fi
else
  nym "scripts/eval.sh up (DVAA bring-up) — PR #20 / T11"
  record "preflight: DVAA up" "NOT YET MERGED" "scripts/eval.sh absent"
fi
advance

hdr "Preflight 3/3 — start the T5 dashboard (loopback)"
if [ -x "$EVAL" ] && [ -f "$REPO/sentinel/dashboard/server.mjs" ]; then
  if bash "$EVAL" dashboard 2>&1 | sed 's/^/  /'; then
    STARTED_DASHBOARD=1; ok "dashboard up: http://127.0.0.1:$DASH_PORT/"; record "preflight: dashboard" PASS "up :$DASH_PORT"
  else
    warn "dashboard did not come up; beats still replay in the terminal"
    record "preflight: dashboard" WARN "did not start"
  fi
else
  nym "T5 dashboard (sentinel/dashboard/server.mjs) — PR #11"
  record "preflight: dashboard" "NOT YET MERGED" "dashboard/eval absent"
fi
advance

# =================================================================================
# BEAT SHEET (demo/SCRIPT.md).  Left = terminal (attacker view), right = dashboard.
# =================================================================================

# ---- Beat 3 — EXPLOIT, red (RAGBot 7005) --------------------------------------
hdr "Beat 3 — EXPLOIT (red) · RAGBot 7005"
say "This is RAGBot on port 7005, an intentionally vulnerable agent from the organizers' DVAA sandbox."
say "We feed it one poisoned document from DVAA's own attack corpus."
if [ -f "$CAP_ATTACK" ]; then
  run_cmd "exploit: tool call + exfil executed" \
    jq -r '.runA.toolCalls[0].function.name, .runA.dvaa.exfilExecuted' "$CAP_ATTACK"
  run_cmd "exploit: secret that left the building" \
    jq -r '.canary.hits[0].query.data' "$CAP_ATTACK"
  say "It called submit_to_index, and the admin secret and an SSN just left the building."
else
  nym "T1 attack capture (captures/attack/aim-ab.demo.json)"
  record "Beat 3 exploit" "NOT YET MERGED" "capture absent"
fi
advance

# ---- Beat 3b — 8KB-evasion (DoD item 1, REQUIRED) -----------------------------
hdr "Beat 3b — 8KB evasion · hide in the middle, DVAA's scanner sees nothing"
say "DVAA's own scanner only looks at the first and last 8KB. This one hides in the middle, so the scanner sees nothing."
if [ -f "${EVASION_MID[0]}" ]; then
  run_cmd "evasion: injection sits between the 8KB head/tail windows (DVAA misses; full scan finds)" evasion_proof_cmd
  if ensure_score; then
    run_cmd "evasion: SentinelProxy (T3) catches both cases DVAA's baseline misses" t3_beats_baseline_cmd
    say "SentinelProxy scans the full payload and never truncates, so it catches exactly the cases the 8KB scan misses."
  else
    bad "scoring output unavailable; cannot show the T3-beats-baseline proof"; record "Beat 3b evasion (T3)" FAIL "no score"
  fi
else
  nym "T6 evasion fixtures (captures/variants/fixtures/evasion/, PR #10/#15)"
  record "Beat 3b evasion" "NOT YET MERGED" "evasion fixtures absent"
fi
advance

# ---- Beat 5a — the AIM twin (RAGBot-AIM 7014) ---------------------------------
hdr "Beat 5a — secure-by-design twin · RAGBot-AIM 7014"
say "Its twin, RAGBot-AIM 7014 — the same code with its capability guard switched on — is denied."
if [ -f "$CAP_ATTACK" ]; then
  # runB has no exfilExecuted key (AIM denies before execution); default to false for a clean readout.
  run_cmd "AIM twin: exfil executed? + denial reason" \
    jq -r '(.runB.dvaa.exfilExecuted // false), .runB.dvaa.aim.denialReason' "$CAP_ATTACK"
else
  nym "T1 attack capture (captures/attack/aim-ab.demo.json)"
  record "Beat 5a AIM twin" "NOT YET MERGED" "capture absent"
fi
advance

# ---- Beat 4 — request-side proxy BLOCK (T2 / PR #14) --------------------------
hdr "Beat 4 — DETECT -> BLOCK (green) · SentinelProxy in front of 7005"
say "Same agent, same document, but now it goes through SentinelProxy."
say "The poisoned request is blocked at the request boundary, before it is ever forwarded to the model — prevention is request-side (T3), not the response-side tripwire, which only raises an alert."
if [ -f "$PROXY_BLOCK_JSONL" ]; then
  run_cmd "proxy block: recorded block-mode verdict, pre-forward (action=blocked_request)" proxy_block_cmd
  say "Blocked before the request reached the model. Nothing was forwarded, so nothing could be exfiltrated."
else
  nym "T2 request-side proxy block (captures/contrast/runs/proxy-block.proxy.jsonl, PR #14)"
  record "Beat 4 proxy block" "NOT YET MERGED" "proxy-block capture absent"
fi
advance

# ---- Beat 4b — egress-guard BLOCK (T12 / t12-egress) --------------------------
hdr "Beat 4b — tool-boundary EGRESS GUARD · fail-closed on exfil"
say "When a request-side block is not the control — like RepoBot, where the proxy only raises an alert — the egress guard is what actually stops the exfil: it denies any destination that came only from untrusted content, and fails closed."
if [ -f "$EGRESS_BLOCK_JSONL" ]; then
  run_cmd "egress guard: exfil destination denied at the tool boundary (honeytoken + allowlist)" egress_block_cmd
else
  nym "T12 egress guard (spike/egress/evidence-block.jsonl, spike PR #18 / branch t12-egress)"
  record "Beat 4b egress guard" "NOT YET MERGED" "egress evidence absent"
fi
advance

# ---- Beat 7 — scoring table (T7 / PR #13) -------------------------------------
hdr "Beat 7 — scoring table · precision / recall / FP / latency"
say "Scored against DVAA's own ground-truth labels: precision, recall, false-positive rate, median latency."
if [ -x "$EVAL" ] && [ -f "$REPO/sentinel/scoring/cli.mjs" ]; then
  if ensure_score; then
    # Show the demo-relevant slice of the cached results: headline + detector table + beats-baseline
    # (the long per-detector false-negative lists are in .eval/score/RESULTS.md).
    printf '  %s$ scripts/eval.sh score   (cached: .eval/score/RESULTS.md)%s\n' "$B" "$Z"
    sed -n '/\*\*Headline/,/^## /p' "$RESULTS_MD" | sed '/^## /d; s/^/    | /'
    ok "scoring: T7 harness table"; record "Beat 7 scoring" PASS "headline live"
  else
    bad "T7 scoring harness did not produce results"; record "Beat 7 scoring" FAIL "no results"
  fi
else
  nym "T7 scoring harness (sentinel/scoring/cli.mjs) — PR #13"
  record "Beat 7 scoring" "NOT YET MERGED" "scoring absent"
fi

# teardown runs on EXIT (trap)
