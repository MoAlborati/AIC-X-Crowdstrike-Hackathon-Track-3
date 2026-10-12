#!/usr/bin/env bash
# demo/run-demo.sh — deterministic driver for the SentinelProxy demo (ticket T9).
#
# Drives the beats of demo/SCRIPT.md on THIS machine, in order, from the committed
# captures/ fixtures. Nothing here makes a live LLM or external API call inside the demo
# window (GOAL.md ground rule): the exploit, the AIM-twin verdict, the egress evidence and
# the metrics replay deterministically from captures/ and sentinel/scoring/results.json.
# The one live step is Beat 4: the real shipped proxy on an ephemeral loopback port in front
# of the offline DVAA RAGBot 7005 (canned replies), benign -> 200, attack -> 403. If it can't
# start, Beat 4 says so (WARN) and shows the recording instead.
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
#   --check-script only check that every spoken line below appears verbatim in demo/SCRIPT.md, and exit
#   -h | --help   this help
#
# Components not yet merged are wired behind a single registry below (see "WIRING
# REGISTRY"). Each prints "NOT YET MERGED: <component>" instead of being skipped
# silently; finalizing them at feature-freeze (14:30) is a one-place edit.
#
# Exit code: 0 if every beat that is wired-and-merged passed; 1 if any row FAILed
# (including the SCRIPT.md sync check). NOT-YET-MERGED and WARN rows do not fail the run.
#
# Spoken lines: every `say "..."` below is a STATIC string and is the source of truth for what the
# presenter says. demo/SCRIPT.md quotes each one verbatim, as a single `> "..."` line. Any number in a
# spoken line is guarded by a check against the evidence, so the run fails if the data changes.
set -uo pipefail

# --------------------------------------------------------------------------- paths
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# --------------------------------------------------------------------------- flags
AUTO=0; DO_DVAA=1; KEEP_DVAA=0; DO_TEARDOWN=1; CHECK_ONLY=0
for a in "$@"; do
  case "$a" in
    --auto) AUTO=1 ;;
    --no-dvaa) DO_DVAA=0 ;;
    --keep-dvaa) KEEP_DVAA=1 ;;
    --no-teardown) DO_TEARDOWN=0 ;;
    --check-script) CHECK_ONLY=1 ;;
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

# T6 8KB-evasion fixtures (PR #10/#15) + T7 scoring results. Beat 3b and Beat 7 read the COMMITTED
# sentinel/scoring/results.json (regenerate with `scripts/eval.sh score`), so the numbers on screen are the
# ones in the repo, with no live recompute inside the 3-min window.
EVASION_MID=("$REPO/captures/variants/fixtures/evasion/eva-pos-middle-001.json" \
             "$REPO/captures/variants/fixtures/evasion/eva-bench-middle-001.json")
SCORE_JSON="$REPO/sentinel/scoring/results.json"
evasion_proof_cmd() {   # DVAA's head/tail 8KB scan misses the mid-document injection; a full scan finds it
  jq -rc '{id, docLength:.baseline8kb.docLength, scanEdgeBytes:.baseline8kb.DETECTION_EDGE,
           injectionAtByte:.baseline8kb.injectionOffsetStart, inMiddleGap:.baseline8kb.inMiddleGap,
           evadesDvaaBaseline:.baseline8kb.evadesBaseline, fullScanFindsSignal:.baseline8kb.signalPresentOnFullScan}' \
    "${EVASION_MID[@]}"
}
evasion_t3_cmd() {   # "8KB evasion: 2/2 fixtures" (never a blanket "beats baseline")
  jq -rc '.beatsBaseline | {evasionFixtures:(.eligible|length), t3Caught:.byDetector.t3.beaten,
           t3Prevented:.byDetector.t3.beatenPrevention, cases:.byDetector.t3.cases}' "$SCORE_JSON" || return 1
  jq -e '.beatsBaseline | (.eligible|length) == 2 and .byDetector.t3.beaten == 2' "$SCORE_JSON" >/dev/null \
    || { echo "results.json no longer shows 8KB evasion 2/2: fix the spoken line"; return 1; }
}
# Beat 7: two headline rows (detection, prevention), T3 vs DVAA's own baseline, with FP, + the evasion result.
headline_cmd() {
  jq -r '
    def pct: (. * 1000 | round) as $x | "\($x / 10 | floor).\($x % 10)%";
    .detectors as $d | .headlineLenses as $h | .counts as $c |
    "corpus: \($c.attack) attack + \($c.benign) benign cases, scored against DVAA ground-truth labels",
    "",
    "                         T3 (SentinelProxy)          DVAA baseline",
    "  detection (any finding)  recall \($h.detection.recall|pct)  FP \($h.detection.falsePositiveRate|pct)        recall \($d["dvaa-baseline"].modes.enforce.anyFinding.recall|pct)  FP \($d["dvaa-baseline"].modes.enforce.anyFinding.falsePositiveRate|pct)",
    "  prevention (pre-forward) recall \($h.prevention.recall|pct)  FP \($h.prevention.falsePositiveRate|pct)        recall \($d["dvaa-baseline"].modes.enforce.prevention.recall|pct)  FP \($d["dvaa-baseline"].modes.enforce.prevention.falsePositiveRate|pct)",
    "",
    "  8KB evasion: \(.beatsBaseline.byDetector.t3.beaten)/\(.beatsBaseline.eligible|length) fixtures (T3)",
    "  in-detector latency: p95 \($d.t3.latencyMs.p95 * 100 | round / 100) ms over \($d.t3.latencyMs.n) cases (under half a millisecond)"' "$SCORE_JSON" || return 1
  jq -e '.detectors.t3.latencyMs.p95 < 0.5' "$SCORE_JSON" >/dev/null || { echo "T3 p95 latency is no longer under half a millisecond: fix the spoken line"; return 1; }
  # Every number in the static Beat 7 spoken line, checked against the file it comes from.
  jq -e '.counts.attack == 189 and .counts.benign == 164
         and ((.detectors["dvaa-baseline"].modes.enforce.anyFinding.falsePositiveRate * 1000 | round) == 128)
         and .headlineLenses.detection.falsePositiveRate == 0 and .headlineLenses.prevention.falsePositiveRate == 0
         and .detectors["dvaa-baseline"].modes.enforce.prevention.recall > .headlineLenses.prevention.recall
         and .detectors["dvaa-baseline"].modes.enforce.anyFinding.recall > .headlineLenses.detection.recall
         and (.beatsBaseline.eligible | length) == 2 and .beatsBaseline.byDetector.t3.beaten == 2' "$SCORE_JSON" >/dev/null \
    || { echo "results.json no longer matches the Beat 7 spoken line (189/164, baseline FP 12.8%, T3 FP 0, baseline higher recall, evasion 2/2): update the say line in run-demo.sh and SCRIPT.md together"; return 1; }
  echo "spoken Beat 7 numbers match results.json"
}

# Beat 4 — request-side proxy block, T3 detector (#24) wired into the shipped proxy CLI (#41).
#  (a) LIVE: start the shipped CLI in block mode on an ephemeral loopback port in front of RAGBot 7005, send a
#      benign question (expect 200, forwarded) and DVAA's own aim-ab request body taken verbatim from the
#      recording (expect 403, refused before forwarding). Falls back to the recording if the proxy or 7005 is down.
#  (b) RECORDED: the T8 contrast run re-recorded with the shipped CLI (captures/contrast/run-contrast.sh,
#      run-meta.json inspector "detector:sentinel-t3"), plus the T4 alert the T10 pipeline built from it
#      (`node sentinel/pipeline/cli.mjs convert captures/contrast/runs/proxy-block.proxy.jsonl`).
PROXY_BLOCK_JSONL="$REPO/captures/contrast/runs/proxy-block.proxy.jsonl"
PROXY_BLOCK_T4="$REPO/captures/contrast/runs/proxy-block.t4-alerts.json"
PROXY_CONFIG="$REPO/sentinel/config/sentinel.config.json"
LIVE_DIR="$REPO/.eval/beat4-live"
# What the narration credits. Every Beat 4 check FAILS if the evidence names a different detector or reason set.
BEAT4_CREDITED_DETECTOR="sentinel-t3"
BEAT4_CREDITED_REASONS='["exfil_instruction_inbound","injection_markers","payee_not_confirmed"]'
BENIGN_BODY='{"messages":[{"role":"user","content":"What does the document indexing service do? One sentence, please."}]}'
LIVE_PID=""; LIVE_PORT=""

blocked_verdicts() {   # file -> [detectors] and [reasons] of FLAGGED verdicts on BLOCKED exchanges (no alert dupes)
  jq -sc '[.[] | select(.type=="exchange" and ((.action // "") | test("block"))) | .verdicts[]? | select(.flagged==true)]
          | {detectors:(map(.detector)|unique), reasons:(map(.reasons[])|unique)}' "$1"
}
check_credit() {   # file -> rc 0 iff the blocked verdicts are exactly the credited detector + reasons
  local got; got="$(blocked_verdicts "$1")"
  local want="{\"detectors\":[\"$BEAT4_CREDITED_DETECTOR\"],\"reasons\":$BEAT4_CREDITED_REASONS}"
  if [ "$got" = "$want" ]; then echo "blocking verdict: $got (matches the spoken credit)"
  else echo "spoken credit $want but the evidence says $got"; return 1; fi
}
live_proxy_start() {
  command -v node >/dev/null 2>&1 || return 1
  curl -fsS --max-time 3 "http://127.0.0.1:7005/health" >/dev/null 2>&1 || { echo "RAGBot 7005 not reachable"; return 1; }
  mkdir -p "$LIVE_DIR"; : > "$LIVE_DIR/proxy.jsonl"; : > "$LIVE_DIR/stdout"
  SENTINEL_MODE=block SENTINEL_LISTEN_PORT=0 SENTINEL_TARGET_PORT=7005 SENTINEL_CAPTURE_PATH="$LIVE_DIR/proxy.jsonl" \
    node "$REPO/sentinel/proxy/cli.mjs" --config "$PROXY_CONFIG" >"$LIVE_DIR/stdout" 2>"$LIVE_DIR/stderr" &
  LIVE_PID=$!
  local i; for i in $(seq 1 50); do
    LIVE_PORT="$(head -1 "$LIVE_DIR/stdout" 2>/dev/null | jq -r 'select(.event=="listening") | .port' 2>/dev/null)"
    [ -n "$LIVE_PORT" ] && break; sleep 0.1
  done
  [ -n "$LIVE_PORT" ] || { echo "proxy did not report a listening port"; live_proxy_stop; return 1; }
  echo "SentinelProxy (shipped CLI, block) on 127.0.0.1:$LIVE_PORT -> 7005, inspectors $(head -1 "$LIVE_DIR/stdout" | jq -c .inspectors)"
}
live_proxy_stop() {
  [ -n "$LIVE_PID" ] || return 0
  kill "$LIVE_PID" 2>/dev/null; wait "$LIVE_PID" 2>/dev/null; LIVE_PID=""
}
live_post() {   # body -> prints HTTP status
  curl -sS -o "$LIVE_DIR/last-body" -w '%{http_code}' --max-time 20 -H 'content-type: application/json' \
    --data-binary "$1" "http://127.0.0.1:$LIVE_PORT/v1/chat/completions"
}
live_benign_cmd() {
  local code; code="$(live_post "$BENIGN_BODY")"
  echo "benign question -> HTTP $code"
  [ "$code" = 200 ] || return 1
}
live_attack_cmd() {
  local body code
  body="$(jq -rs '[.[] | select(.type=="exchange" and .action=="blocked_request")][0].request.body.data' "$PROXY_BLOCK_JSONL")"
  [ -n "$body" ] && [ "$body" != null ] || { echo "no recorded aim-ab request body"; return 1; }
  code="$(live_post "$body")"
  echo "DVAA aim-ab request (poisoned retrieved content in the request) -> HTTP $code"
  [ "$code" = 403 ] || return 1
  live_proxy_stop   # SIGTERM flushes the proxy's capture log before we read it
  jq -c 'select(.type=="exchange" and .request.path=="/v1/chat/completions") | {action, status:.response.status,
         verdicts:[.verdicts[]? | select(.flagged==true) | {detector, reasons}]}' "$LIVE_DIR/proxy.jsonl"
  check_credit "$LIVE_DIR/proxy.jsonl"
}
proxy_block_cmd() {   # the recording: blocked exchange only (the duplicate alert line is not shown)
  jq -rc 'select(.type=="exchange" and ((.action // "") | test("block")))
          | {action, target, status:.response.status,
             verdicts:[.verdicts[] | select(.flagged==true) | {phase, detector, disposition, reasons}]}' "$PROXY_BLOCK_JSONL" || return 1
  jq -e '.inspector == "detector:sentinel-t3" and .inspector_config_is_standin == false' \
    "$REPO/captures/contrast/runs/run-meta.json" >/dev/null || { echo "run-meta.json does not record the T3 detector"; return 1; }
  check_credit "$PROXY_BLOCK_JSONL"
}
# Response-side tripwire claim: in block mode a response carrying a honeytoken is WITHHELD (403
# flagged_response, outcome reply_withheld_tool_already_executed; T3-fix #56). Proven on the real seam: the recorded
# observe-mode exchange (its response carries the planted honeytoken) is replayed through the SHIPPED inspector
# set (buildDefaultInspectors). The response verdict must be flagged, which is what makes block mode withhold it.
# Fails, and so fails the run, on any code where the tripwire is still alert-only.
PROXY_OBSERVE_JSONL="$REPO/captures/contrast/runs/proxy-observe.proxy.jsonl"
withhold_check_cmd() {
  node --input-type=module - "${SENTINEL_CODE_ROOT:-$REPO}" "$PROXY_OBSERVE_JSONL" <<'JS'
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const [root, log] = process.argv.slice(2);
const { loadConfig } = await import(pathToFileURL(`${root}/sentinel/config/load.mjs`));
const { buildDefaultInspectors } = await import(pathToFileURL(`${root}/sentinel/proxy/default-inspectors.mjs`));
const ex = readFileSync(log, 'utf8').split('\n').filter(Boolean).map(JSON.parse)
  .find((r) => r.type === 'exchange' && r.request?.path === '/v1/chat/completions');
if (!ex?.response?.body?.data) { console.log('no recorded chat exchange with a response'); process.exit(1); }
const config = loadConfig({ path: `${root}/sentinel/config/sentinel.config.json` });
const { t3 } = buildDefaultInspectors({ ...config, mode: 'block' }, { write: () => {} });
const base = { path: ex.request.path, headers: ex.request.headers, requestId: 'withhold-check' };
await t3({ ...base, phase: 'request', body: Buffer.from(ex.request.body.data) });
const v = await t3({ ...base, phase: 'response', body: Buffer.from(ex.response.body.data) });
console.log(JSON.stringify({ phase: 'response', detector: v?.detector, flagged: v?.flagged ?? null, disposition: v?.disposition ?? null }));
if (v?.flagged !== true) { console.log('response-side honeytoken is alert-only in this code: block mode would NOT withhold the reply'); process.exit(1); }
console.log('block mode withholds this reply: the secret never reaches the client');
JS
}
t4_alert_cmd() {   # the T4 alert the T10 pipeline built from the recorded verdict
  jq -rc '.runs[][] | {DetectName, RuleId, SeverityName, Atlas:.TechniqueId, OwaspLlm:[.OwaspLlm[].Id],
          Agentic:[.OwaspAgentic[].Id], Oasb:.Oasb.Benchmark, Disposition:.PatternDispositionDescription}' "$PROXY_BLOCK_T4"
}

# T12 — egress guard (sentinel/egress/, PR #45; live demo: scripts/egress-demo.sh). On stage we show the
# RECORDED block-mode run of scripts/egress-demo.sh: the inspector's deny decisions
# (sentinel/egress/evidence-block.jsonl) and the GROUND TRUTH, i.e. what the attacker server received
# (demo/captures/egress-demo-block.txt). DVAA's own exfilExecuted is not ground truth here (it reports
# true even when the egress guard 403s the call).
EGRESS_BLOCK_JSONL="$REPO/sentinel/egress/evidence-block.jsonl"
EGRESS_GROUND_TRUTH="$REPO/demo/captures/egress-demo-block.txt"
egress_block_cmd() {
  # Since #74 the evidence logs non-allowlisted hosts only as host_sha256 (first 16 hex of sha256(host)).
  # Map the two known demo hosts back for display; every deny must get a label, or this row FAILS.
  jq -er --slurp '
    {"df4a066dff40004d":"api.oa2a.org", "e100fbce008c04ec":"canary"} as $known
    | [ .[] | select(.action == "deny")
        | (.host // $known[.host_sha256 // ""]) as $h
        | {host:($h // ("sha256:" + (.host_sha256 // "?"))), action, reasons, canaries:.canary_ids}
          + (if $h == "api.oa2a.org" then {note:"DVAA startup telemetry, blocked by the allowlist"}
             elif (.canary_ids | index("DVAA-ADMIN-PASSWORD")) then {agent:"RAGBot 7005"}
             elif (.canary_ids | index("DVAA-AWS-KEY-ID")) then {agent:"RepoBot 7022 (FAKE credentials)"}
             elif $h == "canary" and (.canary_ids | length) == 0 then {agent:"RepoBot 7022: the poisoned repo'"'"'s bootstrap.sh fetch (no secret in it; denied because the attacker host is not allowlisted)"}
             else {} end) ]
    | (.[] | tostring),
      (if length > 0 and all(.note or .agent) then empty
       else error("an egress deny has no label (unknown host hash or evidence schema change): fix egress_block_cmd") end)
  ' "$EGRESS_BLOCK_JSONL"
}
egress_truth_cmd() {
  grep -E '^RESULT (block|repobot block):|^--- attacker server|^\(no canary hits\)' "$EGRESS_GROUND_TRUTH" || return 1
  grep -q '^RESULT block: PREVENTED' "$EGRESS_GROUND_TRUTH" && grep -q '^RESULT repobot block: PREVENTED' "$EGRESS_GROUND_TRUTH" \
    || { echo "recorded run does not show both RAGBot and RepoBot PREVENTED"; return 1; }
}
# =================================================================================

# SCRIPT.md sync: (a) every say line in this file is static and appears verbatim in SCRIPT.md as `> "<line>"`;
# (b) in the beats this runner drives (3, 3b, 4, 4b, 5a, 7), every `> "..."` line in SCRIPT.md is a say line here.
SCRIPT_MD="$REPO/demo/SCRIPT.md"
script_sync_cmd() {
  python3 - "$SELF" "$SCRIPT_MD" <<'PY'
import re, sys
runner, script = open(sys.argv[1]).read(), open(sys.argv[2]).read()
says, bad = [], []
for n, line in enumerate(runner.splitlines(), 1):
    m = re.match(r'^\s*say (.*)$', line)
    if not m:
        continue
    arg = m.group(1)
    if not re.fullmatch(r'"[^"$`\\]*"', arg):
        bad.append(f"run-demo.sh:{n}: say line is not a static string: {arg[:80]}")
        continue
    says.append(arg[1:-1])
quoted = set(re.findall(r'^> "(.*)"\s*$', script, re.M))
for t in dict.fromkeys(says):
    if t not in quoted:
        bad.append(f'missing from SCRIPT.md (as a single > "..." line): "{t}"')
driven = re.compile(r'^### Beat (3|3b|4|4b|5a|7) ')
section, fenced = None, False
for n, line in enumerate(script.splitlines(), 1):
    if line.startswith('```'):
        fenced = not fenced
        continue
    if fenced:
        continue
    if line.startswith('#'):
        section = line if driven.match(line) else None
        continue
    if section and line.startswith('> '):
        m = re.fullmatch(r'> "(.*)"\s*', line)
        if not m or m.group(1) not in says:
            bad.append(f"SCRIPT.md:{n}: spoken line in a runner-driven beat is not a run-demo.sh say line: {line[:90]}")
for b in bad:
    print(b)
print(f"{len(set(says))} spoken lines checked against demo/SCRIPT.md: {'OK' if not bad else str(len(bad)) + ' mismatch(es)'}")
sys.exit(1 if bad else 0)
PY
}
if [ "$CHECK_ONLY" = 1 ]; then script_sync_cmd; exit $?; fi

STARTED_DASHBOARD=0; STARTED_DVAA=0
teardown() {
  live_proxy_stop
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
  exit "$FINAL_RC"
}
FINAL_RC=0
trap teardown EXIT

print_summary() {
  hdr "Summary"
  { echo "BEAT|RESULT|DETAIL"; printf '%s\n' "${SUMMARY[@]}"; } | \
  awk -F'|' '{printf "  %-34s %-16s %s\n", $1, $2, $3}'
  local fails
  fails=$(printf '%s\n' "${SUMMARY[@]}" | awk -F'|' '$2=="FAIL"' | wc -l | tr -d ' ')
  echo
  if [ "$fails" = 0 ]; then ok "demo run clean — no failing beats"
  else bad "$fails beat(s) FAILED — this is not a clean replay"; FINAL_RC=1; fi
}

# =================================================================================
# PRE-FLIGHT (not part of the 3-minute stage clock)
# =================================================================================
hdr "SentinelProxy demo  ·  mode=$([ "$AUTO" = 1 ] && echo AUTO || echo interactive)"
note "repo: $REPO"
note "SCRIPT: demo/SCRIPT.md    (deterministic replay from captures/)"

hdr "Preflight 0 — spoken lines match demo/SCRIPT.md verbatim"
run_cmd "script sync: every spoken line is verbatim in demo/SCRIPT.md" script_sync_cmd

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
say "We send it one request carrying poisoned retrieved content, the client-side RAG pattern, taken from DVAA's own attack corpus."
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
if [ -f "${EVASION_MID[0]}" ] && [ -f "${EVASION_MID[1]}" ] && [ -f "$SCORE_JSON" ]; then
  run_cmd "evasion: injection sits between the 8KB head/tail windows (DVAA misses; full scan finds)" evasion_proof_cmd
  run_cmd "evasion: 8KB evasion 2/2 fixtures caught by T3 (sentinel/scoring/results.json)" evasion_t3_cmd
  say "SentinelProxy scans the full payload and never truncates. 8KB evasion: 2 out of 2 fixtures caught."
else
  nym "T6 evasion fixtures / T7 results (captures/variants/fixtures/evasion/, sentinel/scoring/results.json)"
  record "Beat 3b evasion" "NOT YET MERGED" "evasion fixtures or results absent"
fi
advance

# ---- Beat 4 — request-side BLOCK: shipped proxy + T3 detector (#14/#24/#41) -----
hdr "Beat 4 — DETECT -> BLOCK (green) · SentinelProxy in front of 7005"
say "Same agent, same request, but now it goes through SentinelProxy. First, a normal question passes untouched."
if [ -f "$PROXY_BLOCK_JSONL" ]; then
  printf '  %s$ live_proxy_start%s\n' "$B" "$Z"
  mkdir -p "$LIVE_DIR"
  if live_proxy_start >"$LIVE_DIR/start.log" 2>&1; then   # not in $(...): LIVE_PID/LIVE_PORT must survive
    sed 's/^/    | /' "$LIVE_DIR/start.log"
    run_cmd "live: benign question forwarded untouched (HTTP 200)" live_benign_cmd
    say "Now the attack."
    run_cmd "live: attack refused before forwarding (HTTP 403), verdict from T3 (sentinel-t3)" live_attack_cmd
    live_proxy_stop
  else
    sed 's/^/    | /' "$LIVE_DIR/start.log"
    live_proxy_stop
    warn "live proxy unavailable; showing the recording"
    record "Beat 4 live proxy" WARN "fell back to the recording"
    run_cmd "recorded: non-attack requests (health checks) forwarded untouched; the recording has no benign chat turn" \
      jq -rc 'select(.type=="exchange" and .action=="forwarded") | {action, path:.request.path, status:.response.status}' "$PROXY_BLOCK_JSONL"
    say "Now the attack."
  fi
  say "Blocked at the request boundary, before it was ever forwarded to the model. The verdict comes from our T3 detector, sentinel-t3, with reason codes exfil_instruction_inbound, injection_markers, payee_not_confirmed. Prevention is request-side. If a honeytoken shows up in a response instead, the tool already ran (alert-only for prevention), but in block mode the reply is withheld, so the secret never reaches the client."
  run_cmd "response-side honeytoken: block mode withholds the reply (shipped inspectors, recorded observe exchange)" withhold_check_cmd
  run_cmd "recorded: same block on the live DVAA run (captures/contrast, detector:sentinel-t3)" proxy_block_cmd
  if [ -f "$PROXY_BLOCK_T4" ]; then
    run_cmd "recorded: the T4 alert built from that verdict (T10 pipeline)" t4_alert_cmd
  else
    nym "T4 alert from the T10 pipeline (captures/contrast/runs/proxy-block.t4-alerts.json)"
    record "Beat 4 T4 alert" "NOT YET MERGED" "alert sidecar absent"
  fi
  say "Nothing was forwarded, so nothing could be exfiltrated."
else
  nym "request-side proxy block (captures/contrast/runs/proxy-block.proxy.jsonl)"
  record "Beat 4 proxy block" "NOT YET MERGED" "proxy-block capture absent"
fi
advance

# ---- Beat 4b — egress guard BLOCK (T12, sentinel/egress/, PR #45) --------------
hdr "Beat 4b — tool-boundary EGRESS GUARD · fail-closed on exfil"
say "When a request-side block is not the control, like RepoBot, which reads its payload inside the agent so the proxy cannot stop the exfil, the egress guard is what stops it. It denies non-allowlisted destinations and honeytokens, and fails closed."
if [ -f "$EGRESS_BLOCK_JSONL" ] && [ -f "$EGRESS_GROUND_TRUTH" ]; then
  run_cmd "egress guard: deny decisions at the tool boundary (sentinel/egress/evidence-block.jsonl)" egress_block_cmd
  say "The api.oa2a.org deny is DVAA's startup telemetry, blocked by the allowlist."
  run_cmd "ground truth: attacker server received nothing, RAGBot 7005 and RepoBot 7022 (scripts/egress-demo.sh block)" egress_truth_cmd
else
  nym "T12 egress guard (sentinel/egress/evidence-block.jsonl + demo/captures/egress-demo-block.txt)"
  record "Beat 4b egress guard" "NOT YET MERGED" "egress evidence absent"
fi
advance

# ---- Beat 5a — the AIM twin (RAGBot-AIM 7014) ---------------------------------
hdr "Beat 5a — secure-by-design twin · RAGBot-AIM 7014"
say "Its twin, RAGBot-AIM 7014, is the same code with its capability guard switched on, and it is denied."
if [ -f "$CAP_ATTACK" ]; then
  # runB has no exfilExecuted key (AIM denies before execution); default to false for a clean readout.
  run_cmd "AIM twin: exfil executed? + denial reason" \
    jq -r '(.runB.dvaa.exfilExecuted // false), .runB.dvaa.aim.denialReason' "$CAP_ATTACK"
  say "Secure-by-design works when you can rebuild the agent. We protect the agents you can't rebuild."
else
  nym "T1 attack capture (captures/attack/aim-ab.demo.json)"
  record "Beat 5a AIM twin" "NOT YET MERGED" "capture absent"
fi
advance

# ---- Beat 7 — headline metrics (T7, sentinel/scoring/results.json) -----------
hdr "Beat 7 — headline · detection and prevention vs DVAA's baseline"
if [ -f "$SCORE_JSON" ]; then
  say "Scored against DVAA's own ground-truth labels on 189 attacks and 164 benign runs. On this corpus DVAA's baseline has the higher recall, and it pays for it in false positives: it flags 12.8 percent of benign traffic, and T3 flags none. 8KB evasion: 2 out of 2 fixtures. In-detector latency is under half a millisecond."
  run_cmd "headline: T3 vs DVAA baseline, detection + prevention + FP (sentinel/scoring/results.json)" headline_cmd
  say "This is a working slice of Falcon AI Detection and Response, at the tool boundary. Thank you."
else
  nym "T7 results (sentinel/scoring/results.json)"
  record "Beat 7 headline" "NOT YET MERGED" "results absent"
fi

# teardown runs on EXIT (trap)
