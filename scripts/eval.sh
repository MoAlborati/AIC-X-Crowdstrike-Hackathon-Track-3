#!/usr/bin/env bash
# eval.sh — one-command local evaluation of every Tourniquet component (T11).
#
# Usage: scripts/eval.sh <target>
#   doctor          check Node >=22 (prefers nvm's >=24), Docker, the pinned DVAA checkout; print fixes
#   up              start the DVAA fleet (docker project dvaa-t1, every port published on 127.0.0.1 only)
#   down            stop the DVAA fleet
#   test            run every *.test.js/*.test.mjs suite under sentinel/, captures/, track3a/ and scripts/;
#                   a test file anywhere else in the repo is an UNGATED FAIL row (never skipped silently)
#                   (found by glob; a missing track dir is reported as NOT YET MERGED "not present"),
#                   print a pass/fail table; exit 1 on any failing suite
#   score           run the T7 scoring harness, print its results table
#   contrast        verify T8's recorded secure-by-design contrast (EVAL_LIVE=1 also re-captures it)
#   dashboard       start the T5 dashboard on loopback in the background, print its URL
#   dashboard-stop  stop the dashboard started by `dashboard`
#   all             doctor, up, test, score, contrast, dashboard; then a summary table
#   track3a         run the Track 3 Path A demo (node track3a/run-demo.mjs; needs Node >= 24, writes .eval/track3a/);
#                   NOT YET MERGED if absent
#   gate <PR#>      MERGE GATE: merge the PR into origin/main in a temp worktree and run `test` there;
#                   exit 1 on a conflict or any failing suite. Required before merging any PR.
#                   Also on the merged tree: claim drift (scripts/claim-drift.mjs: T3/DVAA %s in the pitch docs
#                   must match sentinel/scoring/results.json), demo/run-demo.sh --check-script, and one
#                   demo/run-demo.sh --auto --no-dvaa pass when the PR touches sentinel/detectors,
#                   sentinel/scoring, demo/ or sentinel/dashboard.
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
#   DVAA_DIR, DVAA_PROJECT, DVAA_PIN, DVAA_PLATFORM   forwarded to scripts/setup-dvaa.sh
#   PORTABLE_TIMEOUT_IMPL=perl|bash  force a timeout fallback (testing; default uses timeout/gtimeout)
#
# Runs on Linux/WSL and on macOS stock bash 3.2 + BSD userland (see scripts/lib/portable.sh).
set -uo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SELF_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# EVAL_REPO / EVAL_OUT are set by `gate` to evaluate a temporary merge worktree with this script.
REPO="${EVAL_REPO:-$SELF_REPO}"
OUT="${EVAL_OUT:-$REPO/.eval}"
SETUP_DVAA="$SELF_REPO/scripts/setup-dvaa.sh"
# shellcheck source=lib/portable.sh
. "$SELF_REPO/scripts/lib/portable.sh"   # run_with_timeout, host_os (Linux + macOS bash 3.2 / BSD userland)
HOST_OS="$(host_os)"
export DVAA_DIR="${DVAA_DIR:-$SELF_REPO/.dvaa/dvaa-target}"
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
# Node selection (.nvmrc pins 24): the sentinel/detectors timing budget is calibrated on Node 24, and Node 26
# misses it (#61). Order: `node` on PATH if it is major 24; else the newest major-24 install from nvm,
# $HOME/.cache/node24 (#124) or a keg-only Homebrew node@24 (/opt/homebrew, /usr/local); else `node` on PATH if
# >= 24; else `node` on PATH if >= 22 (WARN in doctor when it is not 24); else the newest nvm/Homebrew node >= 22.
node_major() { "$1" -p 'process.versions.node.split(".")[0]' 2>/dev/null; }
NODE_NOTE=""
node_candidates() {
  local nvm_dir="${NVM_DIR:-$HOME/.nvm}" v
  for v in "$nvm_dir"/versions/node/v*/bin/node "$HOME/.cache/node24/bin/node" \
           /opt/homebrew/opt/node@*/bin/node /usr/local/opt/node@*/bin/node \
           /opt/homebrew/bin/node /usr/local/bin/node; do
    [ -x "$v" ] && echo "$v"
  done
}
select_node() {
  local cur="" cur_major=0 best="" best_major=0 v m
  cur="$(command -v node 2>/dev/null || true)"
  [ -n "$cur" ] && cur_major="$(node_major "$cur")"
  cur_major="${cur_major:-0}"
  if [ "$cur_major" = "$NODE_PREFERRED" ]; then NODE_NOTE="node on PATH"; return 0; fi
  while IFS= read -r v; do
    m="$(node_major "$v")"; m="${m:-0}"
    if [ "$m" = "$NODE_PREFERRED" ]; then best="$v"; best_major="$m"; fi   # last = newest v24 (glob order)
  done < <(node_candidates)
  # No v24 install found: a `node` on PATH that is >= 24 beats falling back to an older (22) install (#124).
  if [ -z "$best" ] && [ "$cur_major" -ge "$NODE_PREFERRED" ]; then NODE_NOTE="node on PATH (v${cur_major}); no Node $NODE_PREFERRED install found"; return 0; fi
  if [ -z "$best" ] && [ "$cur_major" -lt "$NODE_MIN" ]; then
    while IFS= read -r v; do
      m="$(node_major "$v")"; m="${m:-0}"
      if [ "$m" -ge "$NODE_MIN" ] && [ "$m" -gt "$best_major" ]; then best="$v"; best_major="$m"; fi
    done < <(node_candidates)
  fi
  if [ -n "$best" ]; then
    PATH="$(dirname "$best"):$PATH"; export PATH
    NODE_NOTE="$(dirname "$(dirname "$best")") (PATH node was v${cur_major})"
    return 0
  fi
  if [ "$cur_major" -ge "$NODE_MIN" ]; then NODE_NOTE="node on PATH; no Node $NODE_PREFERRED install found"; return 0; fi
  NODE_NOTE="no node >= $NODE_MIN found"; return 1
}
node_fix() { # exact commands to get Node 24 first on PATH
  if [ "$HOST_OS" = macos ]; then
    local kegs="/opt/homebrew/opt"; [ -d /opt/homebrew ] || { [ -d /usr/local/Homebrew ] && kegs="/usr/local/opt"; }
    fix "brew install node@$NODE_PREFERRED && export PATH=$kegs/node@$NODE_PREFERRED/bin:\$PATH   (eval.sh also finds the keg by itself)"
    fix "or with nvm: nvm install $NODE_PREFERRED && nvm use   (reads .nvmrc)"
  else
    fix "nvm install $NODE_PREFERRED && nvm use   (reads .nvmrc)"
  fi
}
require_node() {
  if ! select_node; then
    bad "Node >= $NODE_MIN is required ($NODE_NOTE)"
    node_fix
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
# Install hint for a missing CLI tool, per OS.
pkg_fix() { # tool [brew-name] [apt-name]
  if [ "$HOST_OS" = macos ]; then fix "brew install ${2:-$1}"; else fix "sudo apt-get install -y ${3:-$1}"; fi
}
# Something accepts TCP connections on 127.0.0.1:<port>? (bash /dev/tcp works in macOS bash 3.2 too)
port_listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1; }
port_owner() { # best effort: "cmd(pid)" of the listener, via lsof (macOS always; Linux if installed)
  command -v lsof >/dev/null 2>&1 || return 0
  lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1"("$2")"}' | sort -u | tr '\n' ' '
}
docker_engine() { # docker-desktop | colima | orbstack | other:<name>
  local ctx os
  ctx="$(docker context show 2>/dev/null)"; os="$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)"
  case "$ctx|$os" in
    *colima*) echo colima ;;
    *"Docker Desktop"*|desktop-linux*) echo docker-desktop ;;
    *orbstack*|*OrbStack*) echo orbstack ;;
    *) echo "other:${ctx:-?}/${os:-?}" ;;
  esac
}
# Host ports the demo needs besides DVAA's: proxy listeners in sentinel/config/{sentinel.config,proxy}.json
# and the T5 dashboard.
PROXY_PORTS=(8080 8005)

cmd_doctor() {
  hdr "doctor"
  local rc=0 t m v
  echo "  host: $HOST_OS $(uname -m 2>/dev/null) · bash $BASH_VERSION"

  # bash: every script here is written for bash >= 3.2 (macOS /bin/bash), no bash 4 features needed.
  if [ "${BASH_VERSINFO[0]}" -gt 3 ] || { [ "${BASH_VERSINFO[0]}" = 3 ] && [ "${BASH_VERSINFO[1]}" -ge 2 ]; }; then
    ok "bash $BASH_VERSION (>= 3.2 is enough; macOS stock /bin/bash works)"
  else bad "bash $BASH_VERSION is older than 3.2"; pkg_fix bash; rc=1; fi

  # Run each tool, not just `command -v`: on a fresh Mac, /usr/bin/git and /usr/bin/python3 are stubs that
  # only prompt to install the Xcode Command Line Tools.
  for t in git curl python3; do
    if command -v "$t" >/dev/null 2>&1 && "$t" --version >/dev/null 2>&1; then ok "$t found"
    else bad "$t not found or not runnable"
         if [ "$HOST_OS" = macos ] && [ "$t" != curl ]; then fix "xcode-select --install   (Command Line Tools provide $t)"; else pkg_fix "$t"; fi
         rc=1; fi
  done
  if command -v jq >/dev/null 2>&1; then ok "jq found (demo/run-demo.sh beats)"
  else bad "jq not found (demo/run-demo.sh needs it for every replay beat)"; pkg_fix jq; rc=1; fi
  # Per-suite wall-clock cap: GNU timeout, Homebrew gtimeout, or the perl fallback in scripts/lib/portable.sh.
  if command -v timeout >/dev/null 2>&1; then ok "timeout found (per-suite cap)"
  elif command -v gtimeout >/dev/null 2>&1; then ok "gtimeout found (per-suite cap)"
  elif command -v perl >/dev/null 2>&1; then ok "no GNU timeout; per-suite cap uses the perl fallback (scripts/lib/portable.sh)"
  else bad "no timeout, gtimeout or perl: the per-suite cap cannot be enforced"; pkg_fix timeout coreutils coreutils; rc=1; fi

  if require_node; then
    v="$(node --version)"; m="$(node_major "$(command -v node)")"
    if [ "$m" = "$NODE_PREFERRED" ]; then ok "node $v ($NODE_NOTE; .nvmrc pins $NODE_PREFERRED)"
    elif [ "$m" -gt "$NODE_PREFERRED" ]; then
      warn "node $v ($NODE_NOTE) is newer than the pinned $NODE_PREFERRED: sentinel/detectors timing test fails on Node 26 (#61)"
      node_fix
    else warn "node $v ($NODE_NOTE) is older than the pinned $NODE_PREFERRED: sentinel/alerts declares engines >=24"
         node_fix; fi
    if command -v npm >/dev/null 2>&1; then ok "npm $(npm --version 2>/dev/null)"; else bad "npm not found next to node"; fix "reinstall Node (npm ships with it)"; rc=1; fi
  else rc=1; fi

  local docker_ok=0 sarch harch iarch
  if ! command -v docker >/dev/null 2>&1; then
    bad "docker CLI not found"
    if [ "$HOST_OS" = macos ]; then fix "brew install --cask docker   (Docker Desktop), then: open -a Docker"
    else fix "install Docker Desktop with WSL integration, or docker-ce inside WSL"; fi; rc=1
  elif ! docker info >/dev/null 2>&1; then
    bad "docker daemon not reachable (docker info failed)"
    if [ "$HOST_OS" = macos ]; then fix "open -a Docker   (wait for the whale icon to stop animating), then re-run"
    else fix "start Docker Desktop (Settings > Resources > WSL integration on), or: sudo service docker start"; fi; rc=1
  else
    docker_ok=1
    ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) (daemon reachable; $(docker info --format '{{.OperatingSystem}}' 2>/dev/null))"
    if docker compose version >/dev/null 2>&1; then ok "$(docker compose version | head -n1)"
    else bad "docker compose v2 plugin missing"
         if [ "$HOST_OS" = macos ]; then fix "update Docker Desktop (compose v2 ships with it)"; else fix "sudo apt-get install -y docker-compose-plugin"; fi; rc=1; fi
    # Architecture: DVAA's pinned base image (node:24-alpine by digest) and opena2a/dvaa:0.9.2 are both
    # multi-arch (amd64 + arm64), so on Apple Silicon `up` builds a native arm64 image. An image of the
    # other arch (e.g. built with DVAA_PLATFORM=linux/amd64) runs under emulation: works, but slower.
    harch="$(uname -m)"; sarch="$(docker version --format '{{.Server.Arch}}' 2>/dev/null)"
    iarch="$(docker image inspect "$PROJECT-dvaa" --format '{{.Architecture}}' 2>/dev/null || true)"
    if [ -n "$iarch" ] && [ "$iarch" != "$sarch" ]; then
      warn "host $harch, docker engine $sarch, but image $PROJECT-dvaa is $iarch (emulated; slower)"
      fix "scripts/eval.sh down && docker image rm $PROJECT-dvaa && scripts/eval.sh up   (rebuilds natively)"
    elif [ -n "$iarch" ]; then ok "architecture: host $harch, docker engine $sarch, image $PROJECT-dvaa $iarch (native)"
    else ok "architecture: host $harch, docker engine $sarch (image $PROJECT-dvaa not built yet; up builds it natively)"; fi
    # On macOS Docker runs in a VM and bind mounts only work for paths shared into it; the T12 egress
    # overlay bind-mounts this repo and its log dir. Docker Desktop shares /Users, /Volumes, /private,
    # /tmp, /var/folders by default; Colima shares only $HOME (so not /tmp or $TMPDIR, see #60).
    if [ "$HOST_OS" = macos ]; then
      local engine; engine="$(docker_engine)"
      case "$engine" in
        colima)
          ok "docker engine: Colima (context $(docker context show 2>/dev/null))"
          case "$REPO/" in
            "$HOME"/*) ok "repo is under \$HOME, which Colima shares into its VM" ;;
            *) bad "repo $REPO is outside \$HOME; Colima only shares \$HOME, so bind mounts will be empty"
               fix "clone the repo under ~/ (or start colima with --mount $(dirname "$REPO"):w)"; rc=1 ;;
          esac
          warn "Colima shares only \$HOME: anything bind-mounted from /tmp or \$TMPDIR (/var/folders/...) is empty in containers (#60)"
          fix "TMPDIR=\$HOME/.cache/tmp-docker (mkdir -p it first) for the egress live tests, or use Docker Desktop" ;;
        docker-desktop)
          ok "docker engine: Docker Desktop"
          case "$REPO" in
            /Users/*|/Volumes/*|/private/*|/tmp/*|/var/folders/*) ok "repo is under a Docker Desktop shared path" ;;
            *) warn "repo $REPO is outside Docker Desktop's default shared paths (bind mounts may fail)"
               fix "Docker Desktop > Settings > Resources > File sharing: add $(dirname "$REPO"), or clone under ~/" ;;
          esac ;;
        *) warn "docker engine: $engine (not Docker Desktop or Colima; untested). Bind mounts need the repo shared into its VM" ;;
      esac
    fi
  fi

  if ensure_dvaa_checkout; then ok "DVAA checkout at pinned ${DVAA_PIN:0:12} (clean) in ${DVAA_DIR#$REPO/}"
  else bad "DVAA pinned checkout not available"; rc=1; fi

  local fleet_up=0 p busy="" owner
  if [ "$docker_ok" = 1 ]; then
    if [ -n "$(fleet_containers)" ] && fleet_healthy; then fleet_up=1; ok "DVAA fleet '$PROJECT' running, all ${#DVAA_PORTS[@]} ports healthy"
    else warn "DVAA fleet '$PROJECT' not running/healthy (needed by: up, live seams, contrast EVAL_LIVE=1)"; fix "scripts/eval.sh up"; fi
  fi
  # Ports: DVAA 7001-7023 + 9000 must be free unless our fleet holds them; proxy + dashboard ports likewise.
  if [ "$fleet_up" = 0 ]; then
    for p in "${DVAA_PORTS[@]}"; do port_listening "$p" && busy="$busy $p"; done
    if [ -n "$busy" ]; then
      bad "DVAA ports already in use by something else:$busy"
      for p in $busy; do owner="$(port_owner "$p")"; [ -n "$owner" ] && fix "port $p held by $owner"; done
      fix "lsof -nP -iTCP:<port> -sTCP:LISTEN   then stop that process (or a stale fleet: docker ps | grep -E '700|9000')"; rc=1
    else ok "DVAA ports 7001-7023 + 9000 are free"; fi
  fi
  busy=""
  for p in "${PROXY_PORTS[@]}"; do port_listening "$p" && busy="$busy $p"; done
  if [ -n "$busy" ]; then
    warn "proxy port(s) in use:$busy (sentinel/config listen ports; only needed for a live proxy run)"
    for p in $busy; do owner="$(port_owner "$p")"; [ -n "$owner" ] && fix "port $p held by $owner"; done
    fix "SENTINEL_LISTEN_PORT=<free port> node sentinel/proxy/cli.mjs --config ...   or stop the listener"
  else ok "proxy ports ${PROXY_PORTS[*]} are free"; fi
  if port_listening "$DASH_PORT"; then
    if [ -f "$OUT/dashboard.pid" ] && kill -0 "$(cat "$OUT/dashboard.pid")" 2>/dev/null; then ok "dashboard port $DASH_PORT held by our dashboard (pid $(cat "$OUT/dashboard.pid"))"
    else warn "dashboard port $DASH_PORT is in use by another process $(port_owner "$DASH_PORT")"; fix "EVAL_DASHBOARD_PORT=9101 scripts/eval.sh dashboard"; fi
  else ok "dashboard port $DASH_PORT is free"; fi
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
# Test suites. Discovery is by glob: every directory under SUITE_ROOTS that holds a
# *.test.js or *.test.mjs file is a suite, so a new suite is picked up without editing this script.
# The ticket list below only labels suites and turns a component that is absent into NOT YET MERGED.
SUITE_ROOTS=(sentinel captures track3a scripts demo)
KNOWN_SUITES=(
  "T2|sentinel/proxy"
  "T3|sentinel/detectors"
  "T4|sentinel/alerts"
  "T5|sentinel/dashboard"
  "T7|sentinel/scoring"
  "T6|captures/variants"
  "T8|captures/contrast"
  "3A|track3a"
  "handoff|scripts"
)
# Prints "component_dir|test_dir" per suite. The component dir (the cwd the tests expect) is the parent
# of a test/ or tests/ dir, otherwise the dir itself.
discover_suites() {
  local t comp
  local roots=() r
  for r in "${SUITE_ROOTS[@]}"; do [ -d "$REPO/$r" ] && roots+=("$r"); done
  [ ${#roots[@]} -eq 0 ] && return 0
  ( cd "$REPO" && find "${roots[@]}" \( -name node_modules -o -name .eval -o -name .dvaa \) -prune -o \
      -type f \( -name '*.test.js' -o -name '*.test.mjs' \) -print 2>/dev/null ) \
    | while IFS= read -r t; do dirname "$t"; done | sort -u | while IFS= read -r t; do
      case "$(basename "$t")" in test|tests) comp="$(dirname "$t")" ;; *) comp="$t" ;; esac
      echo "$comp|$t"
    done
}
# Prints every *.test.js/*.test.mjs dir outside SUITE_ROOTS (dot dirs and node_modules pruned; gitignored
# files dropped, e.g. a local scratchpad/, since they are not part of the repo). Such files have no runner in
# this gate; cmd_test turns each into an UNGATED FAIL row so they are never skipped silently.
discover_ungated() {
  local r pat="" list ign
  for r in "${SUITE_ROOTS[@]}"; do pat="$pat|$r"; done
  list="$( ( cd "$REPO" && find . \( -name node_modules -o -name '.?*' \) -prune -o \
      -type f \( -name '*.test.js' -o -name '*.test.mjs' \) -print 2>/dev/null ) \
    | sed 's|^\./||' | grep -Ev "^(${pat#|})/" )"
  [ -n "$list" ] || return 0
  # Outside a git checkout check-ignore fails and nothing is dropped (fail loud, not silent).
  ign="$(printf '%s\n' "$list" | git -C "$REPO" check-ignore --stdin 2>/dev/null)"
  if [ -n "$ign" ]; then list="$(printf '%s\n' "$list" | grep -vxF "$ign")"; fi
  [ -n "$list" ] || return 0
  printf '%s\n' "$list" | while IFS= read -r t; do dirname "$t"; done | sort -u
}
# The command runs the exact discovered files with node --test (so no file can fall outside a
# package.json glob), keeping any --test-* flags the package's own test script sets (e.g. concurrency).
suite_cmd() { # dir testdir
  local dir="$1" tdir="$2" flags="" files
  if [ -f "$REPO/$dir/package.json" ]; then
    flags="$(node -e 'const p=require(process.argv[1]);const s=(p.scripts&&p.scripts.test)||"";process.stdout.write((s.match(/--test-(concurrency|timeout|isolation)=\S+/g)||[]).join(" "))' "$REPO/$dir/package.json")"
  fi
  files="$(cd "$REPO/$dir" && find "${tdir#$dir/}" -maxdepth 1 -type f \( -name '*.test.js' -o -name '*.test.mjs' \) | sort | tr '\n' ' ')"
  [ "$tdir" = "$dir" ] && files="$(cd "$REPO/$dir" && find . -maxdepth 1 -type f \( -name '*.test.js' -o -name '*.test.mjs' \) | sort | tr '\n' ' ')"
  echo "node --test $flags $files"
}
SUITE_ROWS=(); SUITE_FAILS=(); SUITE_MISSING=(); SUITE_SKIPS=()
run_suite() { # ticket dir testdir
  local ticket="$1" dir="$2" tdir="$3" name log cmd rc start secs pass fail skip notes
  name="${dir//\//_}"; log="$OUT/test/$name.log"
  cmd="$(suite_cmd "$dir" "$tdir")"
  start=$(date +%s)
  ( cd "$REPO/$dir" && run_with_timeout "$SUITE_TIMEOUT" bash -c "shopt -s nullglob; $cmd" ) > "$log" 2>&1
  rc=$?; secs=$(( $(date +%s) - start ))
  pass="$(grep -Eo '^(# |ℹ )pass [0-9]+' "$log" | tail -n1 | grep -Eo '[0-9]+$')"
  fail="$(grep -Eo '^(# |ℹ )fail [0-9]+' "$log" | tail -n1 | grep -Eo '[0-9]+$')"
  skip="$(grep -Eo '^(# |ℹ )skipped [0-9]+' "$log" | tail -n1 | grep -Eo '[0-9]+$')"
  notes="log ${log#$SELF_REPO/}"
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
  hdr "test (every *.test.js/*.test.mjs suite under ${SUITE_ROOTS[*]}, found by glob)"
  local root
  for root in "${SUITE_ROOTS[@]}"; do
    [ -d "$REPO/$root" ] || warn "$root/ not present on this branch: none of its suites can run (see NOT YET MERGED below)"
  done
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
  local entry ticket dir tdir rc=0 r nym=0 note
  local suites=() found=" " t2
  while IFS= read -r entry; do suites+=("$entry"); done < <(discover_suites)   # (no mapfile: bash 3.2)
  for entry in ${suites[@]+"${suites[@]}"}; do
    IFS='|' read -r dir tdir <<< "$entry"; found+="$dir "
    ticket="(new)"
    for t2 in "${KNOWN_SUITES[@]}"; do [ "${t2#*|}" = "$dir" ] && ticket="${t2%%|*}"; done
    run_suite "$ticket" "$dir" "$tdir"; r=$?
    [ "$r" = 1 ] && rc=1
  done
  for entry in "${KNOWN_SUITES[@]}"; do
    IFS='|' read -r ticket dir <<< "$entry"
    case "$found" in *" $dir "*) continue ;; esac
    if [ -d "$REPO/$dir" ]; then note="no *.test.js/*.test.mjs under $dir on this branch"; else note="$dir/ not present on this branch"; fi
    SUITE_ROWS+=("$dir|$ticket|NOT YET MERGED|-|-|-|-|$note")
    SUITE_MISSING+=("$ticket $dir"); nym=1
  done
  local ung=()
  while IFS= read -r entry; do ung+=("$entry"); done < <(discover_ungated)
  for entry in ${ung[@]+"${ung[@]}"}; do
    bad "UNGATED: $entry/ has *.test.* files but is outside SUITE_ROOTS (${SUITE_ROOTS[*]}); add it to scripts/eval.sh"
    SUITE_ROWS+=("$entry|(none)|FAIL|-|-|-|-|UNGATED: test files outside SUITE_ROOTS, no runner in this gate")
    rc=1
  done
  if [ ${#suites[@]} -eq 0 ]; then bad "no test files found under ${SUITE_ROOTS[*]}"; return 1; fi
  { echo "SUITE|TICKET|RESULT|PASS|FAIL|SKIP|TIME|NOTES"; printf '%s\n' "${SUITE_ROWS[@]}"; } | print_table
  if [ ${#SUITE_SKIPS[@]} -gt 0 ]; then
    echo; warn "${#SUITE_SKIPS[@]} explicit SKIPPED notice(s) from the suites (optional sources not present):"
    printf '        - %s\n' "${SUITE_SKIPS[@]}"
  fi
  # Machine-readable list for `gate` (one "suite: test name" per line; suite-level failures included).
  { [ ${#SUITE_FAILS[@]} -gt 0 ] && printf '%s\n' "${SUITE_FAILS[@]}"
    printf '%s\n' "${SUITE_ROWS[@]}" | awk -F'|' '$3=="FAIL"{print $1": [suite FAIL] "$8}' | sed 's/; log .*//'; } \
    | sort -u > "$OUT/test/failures.txt"
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
  env ${scoring_env[@]+"${scoring_env[@]}"} nohup node "$srv" --port "$DASH_PORT" --host 127.0.0.1 > "$OUT/dashboard.log" 2>&1 &
  echo $! > "$pidf"
  for _ in $(seq 1 30); do
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
# Track 3 Path A (track3a/, PR #62): OpsBot attacked and defended with Tourniquet. Since #113, run-demo.mjs
# writes its run outputs to the gitignored .eval/track3a/ (override: TRACK3A_OUT), not track3a/runs/. It needs
# Node >= 24 (NODE_USE_ENV_PROXY for the egress-guard stacks; nvm v24.16.0 on the team box) and exits 2 on
# Node < 24, so it is not part of `all` (the default Node on some machines is 22).
cmd_track3a() {
  hdr "track3a (Track 3 Path A: node track3a/run-demo.mjs)"
  require_node || return 1
  if [ ! -f "$REPO/track3a/run-demo.mjs" ]; then
    nym "track3a/ not present on this branch (track3a/run-demo.mjs, PR #62)"; return "$(nym_rc)"
  fi
  mkdir -p "$OUT"
  ( cd "$REPO" && node track3a/run-demo.mjs ) 2>&1 | tee "$OUT/track3a.log" | sed 's/^/  /'
  local rc=${PIPESTATUS[0]}
  if [ "$rc" = 0 ]; then ok "track3a demo exit 0 (log .eval/track3a.log)"
  else bad "track3a demo exit $rc (log .eval/track3a.log)"; return 1; fi
  return 0
}

cmd_dashboard_stop() {
  hdr "dashboard-stop"
  local pidf="$OUT/dashboard.pid"
  if [ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null; then ok "stopped pid $(cat "$pidf")"; rm -f "$pidf"
  else warn "no dashboard started by eval.sh is running"; rm -f "$pidf"; fi
}

# ---------------------------------------------------------------------------------------------------
# Merge gate: PR head merged into the current origin/main, in a throwaway worktree, then `test`.
# A merge conflict or any failing suite fails the gate. Logs: .eval/gate-pr<N>/.
GATE_TMP=""; GATE_TMP2=""
# Demo + claim checks on the merged tree (issue #110, overseer rec #1). Returns 1 if any fails.
#   claim drift   T3/DVAA %s in README/SUBMISSION/QA-PREP/DECK/SCRIPT/PRESENTER must match sentinel/scoring/results.json
#   script sync   demo/run-demo.sh --check-script (spoken lines verbatim in demo/SCRIPT.md)
#   demo --auto   one full replay, only when the PR touches detectors, scoring, demo/ or the dashboard
GATE_DEMO_PATHS='^(sentinel/detectors/|sentinel/scoring/|demo/|sentinel/dashboard/)'
gate_demo_checks() { # merged-tree base-sha pr
  local tree="$1" base="$2" pr="$3" log="$OUT/gate-pr$3/demo" crc=0 changed port
  mkdir -p "$log"
  hdr "gate demo checks (merged tree)"
  if ! require_node; then return 1; fi
  if [ ! -f "$tree/scripts/claim-drift.mjs" ]; then
    bad "claim drift: scripts/claim-drift.mjs missing on the merged tree"; crc=1
  elif node "$tree/scripts/claim-drift.mjs" --repo "$tree" > "$log/claim-drift.log" 2>&1 \
       && node --test "$tree/scripts/test/claim-drift.test.mjs" > "$log/claim-drift-test.log" 2>&1; then
    ok "claim drift: quoted T3/DVAA percentages match sentinel/scoring/results.json"
  else
    bad "claim drift (logs .eval/gate-pr$pr/demo/claim-drift*.log)"
    sed 's/^/        | /' "$log/claim-drift.log" | head -n 12; crc=1
  fi
  if [ ! -x "$tree/demo/run-demo.sh" ]; then
    nym "demo/run-demo.sh not on the merged tree"
  elif bash "$tree/demo/run-demo.sh" --check-script > "$log/check-script.log" 2>&1; then
    ok "demo/run-demo.sh --check-script"
  else
    bad "demo/run-demo.sh --check-script (log .eval/gate-pr$pr/demo/check-script.log)"
    tail -n 8 "$log/check-script.log" | sed 's/^/        | /'; crc=1
  fi
  changed="$(git -C "$tree" diff --name-only "$base" HEAD 2>/dev/null | grep -E "$GATE_DEMO_PATHS" || true)"
  if [ -z "$changed" ]; then
    echo "  SKIP  demo --auto (PR touches none of sentinel/detectors, sentinel/scoring, demo/, sentinel/dashboard)"
  elif [ ! -x "$tree/demo/run-demo.sh" ]; then
    :
  else
    # Own loopback dashboard port per gate run, so parallel gates and a running demo never collide.
    port=$(( 19100 + ($$ % 800) ))
    echo "  demo --auto: PR touches $(echo "$changed" | wc -l | tr -d ' ') demo-relevant file(s), e.g. $(echo "$changed" | head -n 1)"
    if EVAL_DASHBOARD_PORT="$port" run_with_timeout "$SUITE_TIMEOUT" bash "$tree/demo/run-demo.sh" --auto --no-dvaa \
         > "$log/demo-auto.log" 2>&1; then
      ok "demo/run-demo.sh --auto --no-dvaa: every beat PASS (dashboard :$port)"
    else
      bad "demo/run-demo.sh --auto --no-dvaa (log .eval/gate-pr$pr/demo/demo-auto.log)"
      grep -E 'FAIL' "$log/demo-auto.log" | head -n 8 | sed 's/^/        | /'; crc=1
    fi
  fi
  return $crc
}
cmd_gate() {
  local rc
  gate_run "$@"; rc=$?
  if [ -n "$GATE_TMP" ] && [ "${EVAL_KEEP:-0}" != 1 ]; then
    local d
    for d in "$GATE_TMP" "$GATE_TMP2"; do
      [ -n "$d" ] && { git -C "$SELF_REPO" worktree remove --force "$d" >/dev/null 2>&1; rm -rf "$d"; }
    done
  fi
  return $rc
}
gate_run() {
  local pr="${1:-}" tmp ref="refs/eval/pr-${1:-x}" base head merged rc
  hdr "gate PR #${pr:-?} (PR head merged with origin/main, then test)"
  if ! [[ "$pr" =~ ^[0-9]+$ ]]; then bad "usage: scripts/eval.sh gate <PR number>"; return 2; fi
  if ! git -C "$SELF_REPO" fetch -q origin main "+pull/$pr/head:$ref"; then
    bad "could not fetch origin main and pull/$pr/head"; fix "check the PR number and network access to origin"; return 1
  fi
  base="$(git -C "$SELF_REPO" rev-parse origin/main)"; head="$(git -C "$SELF_REPO" rev-parse "$ref")"
  if command -v gh >/dev/null 2>&1; then
    gh pr view "$pr" --json title,baseRefName,state -q '"  PR #'"$pr"': \(.title)  [base \(.baseRefName), \(.state)]"' 2>/dev/null || true
  fi
  echo "  origin/main ${base:0:12}  +  PR head ${head:0:12}"
  if git -C "$SELF_REPO" merge-base --is-ancestor "$head" "$base"; then
    warn "PR #$pr head is already contained in origin/main; the gate re-tests main itself"
  fi
  # Under the repo (gitignored .eval/), not /tmp: some suites assert their paths are repo-local, not /tmp.
  mkdir -p "$SELF_REPO/.eval/gate-worktrees"
  tmp="$(mktemp -d "$SELF_REPO/.eval/gate-worktrees/pr$pr.XXXXXX")"
  GATE_TMP="$tmp"
  if ! git -C "$SELF_REPO" worktree add -q --detach "$tmp" "$base"; then bad "could not create the temp worktree $tmp"; return 1; fi
  if ! git -C "$tmp" -c user.name=eval-gate -c user.email=eval-gate@localhost merge -q --no-ff --no-edit "$head" >/dev/null 2>&1; then
    bad "PR #$pr does not merge cleanly into origin/main; conflicted files:"
    git -C "$tmp" diff --name-only --diff-filter=U | sed 's/^/        - /'
    fix "rebase the PR on main and resolve the conflicts"; return 1
  fi
  merged="$(git -C "$tmp" rev-parse HEAD)"
  echo "  merged tree ${merged:0:12} in $tmp"
  rm -rf "$OUT/gate-pr$pr"
  EVAL_REPO="$tmp" EVAL_OUT="$OUT/gate-pr$pr" EVAL_STRICT=0 bash "$SELF" test; rc=$?
  gate_demo_checks "$tmp" "$base" "$pr" || rc=1
  # Attribute failures: run the same suites on origin/main alone, so a red main is not blamed on the PR.
  if [ "$rc" != 0 ] && [ "$base" != "$merged" ]; then
    local btmp="$tmp.main"
    git -C "$SELF_REPO" worktree add -q --detach "$btmp" "$base" && GATE_TMP2="$btmp"
    EVAL_REPO="$btmp" EVAL_OUT="$OUT/gate-pr$pr/main-baseline" EVAL_STRICT=0 bash "$SELF" test > /dev/null 2>&1
    local mf="$OUT/gate-pr$pr/test/failures.txt" bf="$OUT/gate-pr$pr/main-baseline/test/failures.txt"
    if [ -f "$bf" ]; then
      local new old
      new="$(comm -23 <(grep -v '\[suite FAIL\]' "$mf" | sort) <(grep -v '\[suite FAIL\]' "$bf" | sort))"
      old="$(comm -12 <(grep -v '\[suite FAIL\]' "$mf" | sort) <(grep -v '\[suite FAIL\]' "$bf" | sort))"
      echo
      if [ -n "$new" ]; then bad "failures NEW with this PR (not on origin/main):"; echo "$new" | sed 's/^/        - /'
      else ok "no new test failures from this PR"; fi
      if [ -n "$old" ]; then warn "failures already present on origin/main ${base:0:12} (main is red; not caused by this PR):"; echo "$old" | sed 's/^/        - /'; fi
    fi
  fi
  echo
  if [ "$rc" = 0 ]; then ok "GATE PASS: PR #$pr merged with main ${base:0:12} passes every suite (logs .eval/gate-pr$pr/)"
  else bad "GATE FAIL: PR #$pr merged with main ${base:0:12} is not green. Do not merge. (logs .eval/gate-pr$pr/)"; rc=1; fi
  [ "${EVAL_KEEP:-0}" = 1 ] && echo "  EVAL_KEEP=1: merge worktree kept at $tmp (remove: git worktree remove --force $tmp)"
  return $rc
}

# ---------------------------------------------------------------------------------------------------
cmd_all() {
  local steps=(doctor up test score contrast dashboard) s r rows=() rc=0 label
  for s in "${steps[@]}"; do
    NYM_NOTES=()
    "cmd_$s"; r=$?
    case "$r" in
      0) label=PASS ;;
      "$RC_NYM") label="NOT YET MERGED: $(IFS=';'; echo "${NYM_NOTES[*]-}")" ;;
      *) label=FAIL; rc=1 ;;
    esac
    rows+=("$s|$label")
  done
  hdr "summary"
  { echo "STEP|RESULT"; printf '%s\n' "${rows[@]}"; } | print_table
  [ "$STRICT" = 1 ] && echo "  (EVAL_STRICT=1: NOT YET MERGED counts as FAIL)"
  return $rc
}

usage() { sed -n '2,/^set -uo/p' "$SELF" | sed '$d; s/^# \{0,1\}//'; }

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
  track3a) cmd_track3a ;;
  gate) cmd_gate "${2:-}" ;;
  help|-h|--help) usage ;;
  *) echo "unknown target '$1'" >&2; usage >&2; exit 2 ;;
esac
rc=$?
# 3 = passed with components NOT YET MERGED; report it as success for the shell unless EVAL_STRICT=1.
[ "$rc" = "$RC_NYM" ] && rc=0
exit $rc
