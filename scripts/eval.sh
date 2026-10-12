#!/usr/bin/env bash
# eval.sh — one-command local evaluation of every SentinelProxy component (T11).
#
# Usage: scripts/eval.sh <target>
#   doctor          check Node >=22 (prefers nvm's >=24), Docker, the pinned DVAA checkout; print fixes
#   up              start the DVAA fleet (docker project dvaa-t1, every port published on 127.0.0.1 only)
#   down            stop the DVAA fleet
#   test            run every sentinel/* test suite + the captures/ suites, print a pass/fail table
#   score           run the T7 scoring harness, print its results table
#   contrast        verify T8's recorded secure-by-design contrast (EVAL_LIVE=1 also re-captures it)
#   dashboard       start the T5 dashboard on loopback in the background, print its URL
#   dashboard-stop  stop the dashboard started by `dashboard`
#   all             doctor, up, test, score, contrast, dashboard; then a summary table
#
# Every step prints PASS, FAIL or NOT YET MERGED. Nothing is skipped silently: a component that is not
# on this branch yet prints "NOT YET MERGED" with its ticket, and a failing step exits non-zero.
# Logs and outputs go to .eval/ (gitignored). The committed tree is never modified.
#
# Env knobs:
#   EVAL_STRICT=1             treat NOT YET MERGED as a failure (exit 1). Use for the final judged build.
#   EVAL_LIVE=1               `contrast` also re-captures T8 from the live fleet (needs `up` + git fetch)
#   EVAL_SUITE_TIMEOUT=600    per-suite wall clock cap in seconds; a suite that hits it is a FAIL
#   EVAL_SCORE_ITERATIONS=5   latency iterations per case for `score`
#   EVAL_DASHBOARD_PORT=9100  dashboard port (loopback only)
#   DVAA_DIR, DVAA_PROJECT, DVAA_PIN   forwarded to scripts/setup-dvaa.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/.eval"
SETUP_DVAA="$REPO/scripts/setup-dvaa.sh"
export DVAA_DIR="${DVAA_DIR:-$REPO/.dvaa/dvaa-target}"
PROJECT="${DVAA_PROJECT:-dvaa-t1}"
DVAA_PIN_DEFAULT="$(sed -n 's/^DVAA_PIN="\${DVAA_PIN:-\([0-9a-f]*\)}"$/\1/p' "$SETUP_DVAA")"
DVAA_PIN="${DVAA_PIN:-$DVAA_PIN_DEFAULT}"
SUITE_TIMEOUT="${EVAL_SUITE_TIMEOUT:-600}"
SCORE_ITERATIONS="${EVAL_SCORE_ITERATIONS:-5}"
DASH_PORT="${EVAL_DASHBOARD_PORT:-9100}"
STRICT="${EVAL_STRICT:-0}"
NODE_MIN=22
NODE_PREFERRED=24
# Same port list as scripts/setup-dvaa.sh (API agents, MCP, A2A, DVAA dashboard).
DVAA_PORTS=(7001 7002 7003 7004 7005 7006 7007 7008 7014 7015 7016 7017 7018 7022 7023 7010 7011 7012 7013 7020 7021 9000)

mkdir -p "$OUT"

if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; Z=$'\e[0m'; else R=; G=; Y=; B=; Z=; fi
hdr()  { printf '\n%s== %s ==%s\n' "$B" "$*" "$Z"; }
ok()   { printf '  %sPASS%s  %s\n' "$G" "$Z" "$*"; }
bad()  { printf '  %sFAIL%s  %s\n' "$R" "$Z" "$*"; }
warn() { printf '  %sWARN%s  %s\n' "$Y" "$Z" "$*"; }
NYM_NOTES=()
nym()  { printf '  %sNOT YET MERGED%s  %s\n' "$Y" "$Z" "$*"; NYM_NOTES+=("$*"); }
fix()  { printf '        fix: %s\n' "$*"; }

# Step return codes: 0 PASS, 1 FAIL, 3 NOT YET MERGED (or passed with some components not merged).
RC_NYM=3
nym_rc() { if [ "$STRICT" = 1 ]; then echo 1; else echo "$RC_NYM"; fi; }

# ---------------------------------------------------------------------------------------------------
# Node selection: use `node` on PATH if it is >= 24; otherwise the newest nvm install >= 24; otherwise
# whatever is on PATH if it is >= 22 (sentinel/alerts declares engines >=24, so that is a WARN).
node_major() { "$1" -p 'process.versions.node.split(".")[0]' 2>/dev/null; }
NODE_NOTE=""
select_node() {
  local cur="" cur_major=0 nvm_dir="${NVM_DIR:-$HOME/.nvm}" best="" best_major=0 v m
  cur="$(command -v node 2>/dev/null || true)"
  [ -n "$cur" ] && cur_major="$(node_major "$cur")"
  cur_major="${cur_major:-0}"
  if [ "$cur_major" -ge "$NODE_PREFERRED" ]; then NODE_NOTE="node on PATH"; return 0; fi
  if [ -d "$nvm_dir/versions/node" ]; then
    for v in "$nvm_dir"/versions/node/v*/bin/node; do
      [ -x "$v" ] || continue
      m="$(node_major "$v")"; m="${m:-0}"
      if [ "$m" -gt "$best_major" ]; then best="$v"; best_major="$m"; fi
    done
  fi
  if [ "$best_major" -ge "$NODE_PREFERRED" ]; then
    PATH="$(dirname "$best"):$PATH"; export PATH
    NODE_NOTE="nvm install $(dirname "$(dirname "$best")" | xargs basename) (PATH node was v${cur_major:-none})"
    return 0
  fi
  if [ "$cur_major" -ge "$NODE_MIN" ]; then NODE_NOTE="node on PATH, below preferred $NODE_PREFERRED"; return 0; fi
  NODE_NOTE="no node >= $NODE_MIN found"; return 1
}
require_node() {
  if ! select_node; then
    bad "Node >= $NODE_MIN is required ($NODE_NOTE)"
    fix "nvm install $NODE_PREFERRED   (or install Node $NODE_PREFERRED from nodejs.org), then re-run"
    return 1
  fi
}

# ---------------------------------------------------------------------------------------------------
# DVAA helpers
dvaa_checkout_ok() { # pinned commit + clean tree, no network
  [ -d "$DVAA_DIR/.git" ] || return 1
  [ "$(git -C "$DVAA_DIR" rev-parse HEAD 2>/dev/null)" = "$DVAA_PIN" ] || return 1
  [ -z "$(git -C "$DVAA_DIR" status --porcelain --untracked-files=all 2>/dev/null)" ]
}
ensure_dvaa_checkout() { # uses scripts/setup-dvaa.sh clone, logs to .eval/
  if dvaa_checkout_ok; then return 0; fi
  if ! "$SETUP_DVAA" clone > "$OUT/setup-dvaa-clone.log" 2>&1; then
    bad "scripts/setup-dvaa.sh clone failed (log: .eval/setup-dvaa-clone.log)"
    sed 's/^/        | /' "$OUT/setup-dvaa-clone.log" | tail -n 5
    fix "check network access to github.com, or point DVAA_DIR at a clean checkout of $DVAA_PIN"
    return 1
  fi
  dvaa_checkout_ok
}
port_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$1${2:-/health}" 2>/dev/null || true; }
fleet_down_ports() { # prints ports whose health endpoint is not 200
  local p ep
  for p in "${DVAA_PORTS[@]}"; do
    ep=/health; [ "$p" = 9000 ] && ep=/stats
    [ "$(port_code "$p" "$ep")" = 200 ] || printf '%s ' "$p"
  done
}
fleet_healthy() { [ -z "$(fleet_down_ports)" ]; }
fleet_containers() { docker ps --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' 2>/dev/null; }
# Prints every published port mapping of the project that is NOT bound to loopback.
fleet_exposed() {
  docker ps --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Ports}}' 2>/dev/null \
    | tr ',' '\n' | sed 's/^ *//' | grep -- '->' | grep -Ev '^(127\.0\.0\.1|\[::1\]):' || true
}

# ---------------------------------------------------------------------------------------------------
cmd_doctor() {
  hdr "doctor"
  local rc=0 t m v
  for t in git curl python3 timeout; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t found"; else bad "$t not found"; fix "sudo apt-get install -y $t"; rc=1; fi
  done

  if require_node; then
    v="$(node --version)"; m="$(node_major "$(command -v node)")"
    if [ "$m" -ge "$NODE_PREFERRED" ]; then ok "node $v ($NODE_NOTE)"
    else warn "node $v ($NODE_NOTE). sentinel/alerts declares engines >=24; its tests pass on 22 today"
         fix "nvm install $NODE_PREFERRED"; fi
    if command -v npm >/dev/null 2>&1; then ok "npm $(npm --version 2>/dev/null)"; else bad "npm not found next to node"; fix "reinstall Node (npm ships with it)"; rc=1; fi
  else rc=1; fi

  if ! command -v docker >/dev/null 2>&1; then
    bad "docker CLI not found"; fix "install Docker Desktop with WSL integration, or docker-ce inside WSL"; rc=1
  elif ! docker info >/dev/null 2>&1; then
    bad "docker daemon not reachable (docker info failed)"
    fix "start Docker Desktop (Settings > Resources > WSL integration on), or: sudo service docker start"; rc=1
  else
    ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) (daemon reachable)"
    if docker compose version >/dev/null 2>&1; then ok "$(docker compose version | head -n1)"
    else bad "docker compose v2 plugin missing"; fix "sudo apt-get install -y docker-compose-plugin"; rc=1; fi
  fi

  if ensure_dvaa_checkout; then ok "DVAA checkout at pinned ${DVAA_PIN:0:12} (clean) in ${DVAA_DIR#$REPO/}"
  else bad "DVAA pinned checkout not available"; rc=1; fi

  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if [ -n "$(fleet_containers)" ] && fleet_healthy; then ok "DVAA fleet '$PROJECT' running, all ${#DVAA_PORTS[@]} ports healthy"
    else warn "DVAA fleet '$PROJECT' not running/healthy (needed by: up, live seams, contrast EVAL_LIVE=1)"; fix "scripts/eval.sh up"; fi
  fi
  return $rc
}

cmd_up() {
  hdr "up (DVAA fleet, project $PROJECT, loopback only)"
  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    bad "docker is not available"; fix "scripts/eval.sh doctor"; return 1
  fi
  ensure_dvaa_checkout || return 1
  if [ -n "$(fleet_containers)" ] && fleet_healthy; then
    ok "fleet already running and healthy; leaving it as is (other users may share it)"
  else
    echo "  starting fleet via scripts/setup-dvaa.sh up (first build can take a few minutes; log: .eval/setup-dvaa-up.log)"
    if ! DVAA_PROJECT="$PROJECT" "$SETUP_DVAA" up > "$OUT/setup-dvaa-up.log" 2>&1; then
      bad "scripts/setup-dvaa.sh up failed"; tail -n 15 "$OUT/setup-dvaa-up.log" | sed 's/^/        | /'
      fix "read .eval/setup-dvaa-up.log; port clash? docker ps --format '{{.Names}} {{.Ports}}' | grep -E '700|9000'"
      return 1
    fi
  fi
  local down exposed wd head
  down="$(fleet_down_ports)"
  if [ -n "$down" ]; then
    bad "unhealthy DVAA ports: $down"; fix "docker compose -p $PROJECT logs --tail 50; then scripts/eval.sh down && scripts/eval.sh up"; return 1
  fi
  ok "all ${#DVAA_PORTS[@]} DVAA ports answer 200 (agents 7001-7023, dashboard 9000)"
  exposed="$(fleet_exposed)"
  if [ -n "$exposed" ]; then
    bad "fleet publishes ports beyond loopback: $(echo "$exposed" | tr '\n' ' ')"
    fix "scripts/eval.sh down; DVAA's docker-compose.yml must map 127.0.0.1:<port>:<port>"; return 1
  fi
  ok "every published port is bound to 127.0.0.1"
  # Provenance: which checkout was the running fleet built from?
  wd="$(docker inspect "$(fleet_containers | head -n1)" --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' 2>/dev/null)"
  head="$(git -C "$wd" rev-parse HEAD 2>/dev/null || true)"
  if [ "$head" = "$DVAA_PIN" ]; then ok "fleet built from $wd at pinned ${DVAA_PIN:0:12}"
  else warn "fleet built from '$wd' at '${head:-unknown}', not verifiably the pin ${DVAA_PIN:0:12}"
       fix "scripts/eval.sh down && scripts/eval.sh up   (rebuilds from ${DVAA_DIR#$REPO/})"; fi
  echo "  DVAA dashboard: http://127.0.0.1:9000"
  return 0
}

cmd_down() {
  hdr "down"
  ensure_dvaa_checkout || return 1
  DVAA_PROJECT="$PROJECT" "$SETUP_DVAA" down && ok "fleet $PROJECT stopped"
}

# ---------------------------------------------------------------------------------------------------
# Test suites. Known components are listed with their ticket so a missing one prints NOT YET MERGED.
# Any other sentinel/<x>/ that has tests is discovered and run too, so new components are never missed.
KNOWN_SUITES=(
  "T2|sentinel/proxy|sentinel/proxy/test"
  "T3|sentinel/detectors|sentinel/detectors/test"
  "T4|sentinel/alerts|sentinel/alerts/test"
  "T5|sentinel/dashboard|sentinel/dashboard/test"
  "T7|sentinel/scoring|sentinel/scoring/test"
  "T6|captures/variants|captures/variants/tests"
  "T8|captures/contrast|captures/contrast/tests"
)
suite_cmd() { # dir testdir -> prints the command to run, cwd = dir
  local dir="$1" tdir="$2" script
  if [ -f "$REPO/$dir/package.json" ]; then
    script="$(node -e 'const p=require(process.argv[1]);process.stdout.write((p.scripts&&p.scripts.test)||"")' "$REPO/$dir/package.json")"
    if [ -n "$script" ]; then echo "npm test --silent"; return; fi
  fi
  echo "node --test ${tdir#$dir/}/*.test.js ${tdir#$dir/}/*.test.mjs"
}
SUITE_ROWS=(); SUITE_FAILS=(); SUITE_MISSING=(); SUITE_SKIPS=()
run_suite() { # ticket dir testdir
  local ticket="$1" dir="$2" tdir="$3" name log cmd rc start secs pass fail skip notes
  name="${dir//\//_}"; log="$OUT/test/$name.log"
  if [ ! -d "$REPO/$tdir" ]; then
    SUITE_ROWS+=("$dir|$ticket|NOT YET MERGED|-|-|-|-|$tdir not on this branch")
    SUITE_MISSING+=("$ticket $dir"); return "$RC_NYM"
  fi
  cmd="$(suite_cmd "$dir" "$tdir")"
  start=$(date +%s)
  ( cd "$REPO/$dir" && shopt -s nullglob && eval "timeout --kill-after=10 $SUITE_TIMEOUT $cmd" ) > "$log" 2>&1
  rc=$?; secs=$(( $(date +%s) - start ))
  pass="$(grep -Eo '^(# |ℹ )pass [0-9]+' "$log" | tail -n1 | grep -Eo '[0-9]+$')"
  fail="$(grep -Eo '^(# |ℹ )fail [0-9]+' "$log" | tail -n1 | grep -Eo '[0-9]+$')"
  skip="$(grep -Eo '^(# |ℹ )skipped [0-9]+' "$log" | tail -n1 | grep -Eo '[0-9]+$')"
  notes="log .eval/test/$name.log"
  # Explicit skip notices printed by the suites themselves (not test names that mention SKIPPED).
  local sk n=0
  while IFS= read -r sk; do SUITE_SKIPS+=("$dir: $sk"); n=$((n + 1)); done < <(
    grep -E 'SKIPPED' "$log" | grep -Ev '^[[:space:]]*(✔|✖|﹣|ok |not ok |#)' | sort -u)
  [ "$n" -gt 0 ] && notes="$n explicit SKIPPED notice(s), listed below; $notes"
  local result=PASS
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then result=FAIL; notes="TIMED OUT after ${SUITE_TIMEOUT}s; $notes"
  elif [ "$rc" != 0 ]; then result=FAIL
  elif [ -z "$pass" ] || [ "$pass" = 0 ]; then result=FAIL; notes="ran zero tests; $notes"; fi
  SUITE_ROWS+=("$dir|$ticket|$result|${pass:-?}|${fail:-?}|${skip:-?}|${secs}s|$notes")
  if [ "$result" = FAIL ]; then
    local f
    while IFS= read -r f; do SUITE_FAILS+=("$dir: $f"); done < <(
      { grep -E '^not ok [0-9]+ - ' "$log" | sed -E 's/^not ok [0-9]+ - //'
        sed -n '/failing tests:/,$p' "$log" | grep -E '^✖ ' | grep -v 'failing tests:' | sed -E 's/^✖ //; s/ \([0-9.]+m?s\)$//'; } | sort -u)
    return 1
  fi
  return 0
}
print_table() { # header, then rows on stdin, '|' separated
  python3 -c '
import sys
rows=[l.rstrip("\n").split("|") for l in sys.stdin if l.strip()]
w=[max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
for k,r in enumerate(rows):
    print("  "+"  ".join(c.ljust(w[i]) for i,c in enumerate(r)).rstrip())
    if k==0: print("  "+"  ".join("-"*x for x in w))
'
}
cmd_test() {
  hdr "test (every sentinel/* suite + captures suites)"
  require_node || return 1
  mkdir -p "$OUT/test"
  # Real seams: the pinned DVAA checkout (T6 evasion proof, T7 baseline) and, when the fleet is up,
  # the live DVAA port (T2). If the fleet is down, the live tests report their own skips in the table.
  local have_dvaa=0
  ensure_dvaa_checkout && have_dvaa=1
  if [ "$have_dvaa" = 1 ]; then export DVAA_SRC="$DVAA_DIR" DVAA_REQUIRE_REAL=1
  else warn "no DVAA checkout: real-DVAA seams will report SKIPPED"; fi
  if fleet_healthy; then export SENTINEL_REQUIRE_DVAA=1; echo "  DVAA fleet up: live-DVAA seams are required (SENTINEL_REQUIRE_DVAA=1)"
  else warn "DVAA fleet not up: live-DVAA seams will be skipped (run scripts/eval.sh up first)"; fi

  SUITE_ROWS=(); SUITE_FAILS=(); SUITE_MISSING=(); SUITE_SKIPS=()
  local entry ticket dir tdir rc=0 r nym=0 known=" " d
  for entry in "${KNOWN_SUITES[@]}"; do
    IFS='|' read -r ticket dir tdir <<< "$entry"; known+="$dir "
    run_suite "$ticket" "$dir" "$tdir"; r=$?
    [ "$r" = 1 ] && rc=1; [ "$r" = "$RC_NYM" ] && nym=1
  done
  for d in "$REPO"/sentinel/*/; do
    d="${d%/}"; d="${d#$REPO/}"
    case "$known" in *" $d "*) continue ;; esac
    [ -d "$REPO/$d/test" ] || [ -d "$REPO/$d/tests" ] || continue
    tdir="$d/test"; [ -d "$REPO/$tdir" ] || tdir="$d/tests"
    run_suite "(new)" "$d" "$tdir"; [ $? = 1 ] && rc=1
  done
  { echo "SUITE|TICKET|RESULT|PASS|FAIL|SKIP|TIME|NOTES"; printf '%s\n' "${SUITE_ROWS[@]}"; } | print_table
  if [ ${#SUITE_SKIPS[@]} -gt 0 ]; then
    echo; warn "${#SUITE_SKIPS[@]} explicit SKIPPED notice(s) from the suites (optional sources not present):"
    printf '        - %s\n' "${SUITE_SKIPS[@]}"
  fi
  if [ ${#SUITE_FAILS[@]} -gt 0 ]; then
    echo; bad "${#SUITE_FAILS[@]} failing test(s):"
    printf '        - %s\n' "${SUITE_FAILS[@]}"
  fi
  [ "$rc" = 1 ] && return 1
  if [ "$nym" = 1 ]; then nym "suites for $(IFS=,; echo "${SUITE_MISSING[*]}" | sed 's/,/, /g')"; return "$(nym_rc)"; fi
  return 0
}

# ---------------------------------------------------------------------------------------------------
cmd_score() {
  hdr "score (T7 scoring harness)"
  require_node || return 1
  if [ ! -f "$REPO/sentinel/scoring/cli.mjs" ]; then nym "T7 scoring harness (sentinel/scoring/cli.mjs)"; return "$(nym_rc)"; fi
  ensure_dvaa_checkout && export DVAA_SRC="$DVAA_DIR"
  mkdir -p "$OUT/score"
  node "$REPO/sentinel/scoring/cli.mjs" --iterations "$SCORE_ITERATIONS" \
    --out "$OUT/score/results.json" --md "$OUT/score/RESULTS.md" \
    > "$OUT/score/stdout.md" 2> "$OUT/score/stderr.log"
  local rc=$?
  sed 's/^/  /' "$OUT/score/stdout.md"
  echo
  case "$rc" in
    0) ok "harness exit 0; results in .eval/score/{results.json,RESULTS.md}" ;;
    1) bad "harness exit 1: detector errors (headline withheld), label warnings or DVAA pin drift"
       sed 's/^/        | /' "$OUT/score/stderr.log" | tail -n 20; return 1 ;;
    *) bad "harness exit $rc: bound/corpus error, nothing scored"
       sed 's/^/        | /' "$OUT/score/stderr.log" | tail -n 20; return 1 ;;
  esac
  if [ ! -f "$REPO/sentinel/detectors/index.js" ]; then
    nym "T3 detector (sentinel/detectors): headline withheld; table shows baselines only"
    return "$(nym_rc)"
  fi
  return 0
}

cmd_contrast() {
  hdr "contrast (T8 secure-by-design A/B)"
  require_node || return 1
  local c="$REPO/captures/contrast"
  if [ ! -f "$c/build-contrast.mjs" ]; then nym "T8 contrast (captures/contrast/, PR #16)"; return "$(nym_rc)"; fi
  # Verify the recorded evidence on a copy, so contrast.json in the tree is never rewritten.
  rm -rf "$OUT/contrast/recorded"; mkdir -p "$OUT/contrast"
  cp -r "$c/runs" "$OUT/contrast/recorded"
  echo "  recorded runs (captures/contrast/runs), recomputed and checked against ground truth:"
  if ! node "$c/build-contrast.mjs" "$OUT/contrast/recorded" 2>&1 | sed 's/^/  /'; then
    bad "recorded contrast failed its ground-truth checks"; return 1
  fi
  ok "recorded contrast holds"
  if [ "${EVAL_LIVE:-0}" = 1 ]; then
    echo "  EVAL_LIVE=1: re-capturing from the live fleet into .eval/contrast/live"
    if ! "$c/run-contrast.sh" "$OUT/contrast/live" 2>&1 | sed 's/^/  /'; then
      bad "live contrast re-capture failed"; fix "scripts/eval.sh up; git fetch origin; see captures/contrast/README.md"; return 1
    fi
    ok "live contrast re-captured and holds"
  else
    echo "  (live re-capture not run; set EVAL_LIVE=1 with the fleet up)"
  fi
  return 0
}

# ---------------------------------------------------------------------------------------------------
cmd_dashboard() {
  hdr "dashboard (T5, loopback only)"
  require_node || return 1
  local srv="$REPO/sentinel/dashboard/server.mjs" pidf="$OUT/dashboard.pid" url="http://127.0.0.1:$DASH_PORT/"
  if [ ! -f "$srv" ]; then nym "T5 dashboard (sentinel/dashboard/server.mjs)"; return "$(nym_rc)"; fi
  if [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null && [ "$(port_code "$DASH_PORT")" = 200 ]; then
    ok "already running (pid $(cat "$pidf")): $url"; return 0
  fi
  if [ "$(port_code "$DASH_PORT")" != 000 ] && [ -n "$(port_code "$DASH_PORT")" ]; then
    bad "port $DASH_PORT is already in use by another process"; fix "EVAL_DASHBOARD_PORT=9101 scripts/eval.sh dashboard"; return 1
  fi
  # Show the freshly scored results when `score` ran, else the committed sentinel/scoring/results.json.
  local scoring_env=()
  [ -f "$OUT/score/results.json" ] && scoring_env=(SENTINEL_SCORING_FILE="$OUT/score/results.json")
  env "${scoring_env[@]}" nohup node "$srv" --port "$DASH_PORT" --host 127.0.0.1 > "$OUT/dashboard.log" 2>&1 &
  echo $! > "$pidf"
  local i
  for i in $(seq 1 30); do
    [ "$(port_code "$DASH_PORT")" = 200 ] && break
    kill -0 "$(cat "$pidf")" 2>/dev/null || break
    sleep 0.5
  done
  if [ "$(port_code "$DASH_PORT")" != 200 ]; then
    bad "dashboard did not come up on 127.0.0.1:$DASH_PORT within 15s"; sed 's/^/        | /' "$OUT/dashboard.log" | tail -n 10
    rm -f "$pidf"; return 1
  fi
  local n
  n="$(curl -s --max-time 5 "http://127.0.0.1:$DASH_PORT/api/captures" | node -e '
    let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);const a=Array.isArray(j)?j:(j.captures||[]);process.stdout.write(String(a.length))}catch{process.stdout.write("?")}})')"
  if [ "$n" = "?" ] || [ "$n" = 0 ]; then bad "dashboard is up but /api/captures returned no captures"; return 1; fi
  ok "dashboard up (pid $(cat "$pidf")), $n captures available for replay"
  echo
  echo "  ${B}open: $url${Z}"
  echo "  log: .eval/dashboard.log   stop: scripts/eval.sh dashboard-stop"
  return 0
}
cmd_dashboard_stop() {
  hdr "dashboard-stop"
  local pidf="$OUT/dashboard.pid"
  if [ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null; then ok "stopped pid $(cat "$pidf")"; rm -f "$pidf"
  else warn "no dashboard started by eval.sh is running"; rm -f "$pidf"; fi
}

# ---------------------------------------------------------------------------------------------------
cmd_all() {
  local steps=(doctor up test score contrast dashboard) s r rows=() rc=0 label
  for s in "${steps[@]}"; do
    NYM_NOTES=()
    "cmd_$s"; r=$?
    case "$r" in
      0) label=PASS ;;
      "$RC_NYM") label="NOT YET MERGED: $(IFS=';'; echo "${NYM_NOTES[*]}")" ;;
      *) label=FAIL; rc=1 ;;
    esac
    rows+=("$s|$label")
  done
  hdr "summary"
  { echo "STEP|RESULT"; printf '%s\n' "${rows[@]}"; } | print_table
  [ "$STRICT" = 1 ] && echo "  (EVAL_STRICT=1: NOT YET MERGED counts as FAIL)"
  return $rc
}

usage() { sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

case "${1:-help}" in
  doctor) cmd_doctor ;;
  up) cmd_up ;;
  down) cmd_down ;;
  test) cmd_test ;;
  score) cmd_score ;;
  contrast) cmd_contrast ;;
  dashboard) cmd_dashboard ;;
  dashboard-stop) cmd_dashboard_stop ;;
  all) cmd_all ;;
  help|-h|--help) usage ;;
  *) echo "unknown target '$1'" >&2; usage >&2; exit 2 ;;
esac
rc=$?
# 3 = passed with components NOT YET MERGED; report it as success for the shell unless EVAL_STRICT=1.
[ "$rc" = "$RC_NYM" ] && rc=0
exit $rc
