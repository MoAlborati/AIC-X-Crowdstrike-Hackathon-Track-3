#!/usr/bin/env bash
# run-contrast.sh — T8 secure-by-design contrast, captured from the real DVAA fleet.
#
# Three columns, one attack (DVAA's own bundled `demo aim-ab` payload APWN-DE-003):
#   1. vulnerable   RAGBot 7005 direct                      -> exfil executes
#   2. defended     RAGBot-AIM 7014 (AIM twin), SecureBot 7001 -> refused / denied
#   3. proxied      RAGBot 7005 behind SentinelProxy         -> blocked before the agent runs
#
# We author NO attack content. Every request is sent by DVAA's own `demo aim-ab` runner;
# we only point its second run ("run B") at a different port through the env knobs the runner
# already supports (DVAA_RAGBOT_AIM_PORT, DVAA_BASE). Run A is always the unmodified vulnerable
# RAGBot, so every file carries its own positive control.
#
# SentinelProxy runs in a throwaway container that shares the DVAA container's network namespace,
# so the demo's 127.0.0.1 canary and the proxy see the same loopback as the agents.
#
# Detector: until `origin/t3-detector-core` exists, the proxy uses T2's substring inspector with
# the STAND-IN needle list in standin-inspector.config.json. That proves the proxy's block path,
# not detection quality. If the T3 branch exists, this script refuses to run on the stand-in
# (fail loud) unless SENTINEL_ALLOW_STANDIN=1. A T3 ref paired with the stand-in config is always
# refused. run-meta.json's "inspector" is derived from the detector field the proxy actually
# logged, never from the ref name, and build-contrast.mjs fails if the two disagree.
#
# Usage: captures/contrast/run-contrast.sh [OUT_DIR]   (default: captures/contrast/runs)
# Env:   DVAA_CONTAINER (dvaa-t1-dvaa-1)  DVAA_IMAGE (dvaa-t1-dvaa)
#        SENTINEL_REF   (origin/main)            PROXY_PORT (7099, inside the DVAA netns)
#        SENTINEL_CONFIG (captures/contrast/standin-inspector.config.json)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CONTAINER="${DVAA_CONTAINER:-dvaa-t1-dvaa-1}"
IMAGE="${DVAA_IMAGE:-dvaa-t1-dvaa}"
SENTINEL_REF="${SENTINEL_REF:-origin/main}"
PROXY_PORT="${PROXY_PORT:-7099}"
SENTINEL_CONFIG="${SENTINEL_CONFIG:-$HERE/standin-inspector.config.json}"
OUT="$(mkdir -p "${1:-$HERE/runs}" && cd "${1:-$HERE/runs}" && pwd)"
PROXY_NAME="t8-sentinel-proxy-$$"
# shellcheck source=../../scripts/lib/portable.sh
. "$REPO/scripts/lib/portable.sh"   # sha256_file: sha256sum on Linux, shasum -a 256 on macOS

die() { echo "run-contrast: ERROR: $*" >&2; exit 1; }

# --- detector selection (fail loud, never silently stay on the stand-in) -------------------------
# The stand-in is any config that wires T2's substring inspector (inspect.flagSubstrings).
is_standin_config() {
  python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); sys.exit(0 if (c.get("inspect") or {}).get("flagSubstrings") else 1)' "$1"
}
[[ -f "$SENTINEL_CONFIG" ]] || die "SENTINEL_CONFIG $SENTINEL_CONFIG not found"
STANDIN_CFG=0; is_standin_config "$SENTINEL_CONFIG" && STANDIN_CFG=1
# A T3 ref must never run on the stand-in needles: the table would credit T3 with substring matches.
# No override; SENTINEL_ALLOW_STANDIN does not apply here.
if [[ "$SENTINEL_REF" == *t3* && "$STANDIN_CFG" == 1 ]]; then
  die "SENTINEL_REF=$SENTINEL_REF is a T3 ref but SENTINEL_CONFIG=$SENTINEL_CONFIG is the stand-in config
  (inspect.flagSubstrings). Refusing to pair them. Point SENTINEL_CONFIG at a config that wires T3's inspector."
fi
if [[ "$STANDIN_CFG" == 1 ]] && [[ "${SENTINEL_ALLOW_STANDIN:-0}" != 1 ]] \
   && git -C "$REPO" rev-parse --verify --quiet origin/t3-detector-core >/dev/null; then
  die "origin/t3-detector-core exists but SENTINEL_CONFIG is the stand-in inspector.
  Switch column 3 to the T3 detector (SENTINEL_REF + SENTINEL_CONFIG), or set
  SENTINEL_ALLOW_STANDIN=1 to knowingly re-run the stand-in."
fi
git -C "$REPO" rev-parse --verify --quiet "$SENTINEL_REF" >/dev/null || die "unknown SENTINEL_REF $SENTINEL_REF (git fetch origin?)"
SENTINEL_SHA="$(git -C "$REPO" rev-parse "$SENTINEL_REF")"

docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true || die "DVAA container $CONTAINER is not running (scripts/setup-dvaa.sh up)"
for p in 7001 7005 7014; do
  curl -sf --max-time 3 "http://127.0.0.1:$p/health" >/dev/null || die "DVAA port $p is not healthy"
done

# --- proxy code: exact tree from SENTINEL_REF, nothing copied into this repo ----------------------
WORK="$(mktemp -d)"
cleanup() { docker rm -f "$PROXY_NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
git -C "$REPO" archive "$SENTINEL_REF" sentinel/proxy sentinel/config sentinel/alerts | tar -x -C "$WORK"
cp "$SENTINEL_CONFIG" "$WORK/contrast.config.json"
mkdir -p "$WORK/out" && chmod 777 "$WORK/out"

demo() { # name [ENV=VAL ...] ; runs DVAA's own aim-ab runner, keeps its JSON even on exit 1
  local name="$1"; shift
  local envs=(-e DVAA_BASE=http://127.0.0.1)
  for kv in "$@"; do envs+=(-e "$kv"); done
  set +e
  docker exec "${envs[@]}" "$CONTAINER" node src/index.js demo aim-ab --json > "$OUT/$name.demo.json"
  local rc=$?
  set -e
  # DVAA's verdict() only passes when run B is an AIM agent, so redirected runs exit 1 by design.
  echo "  $name: dvaa demo exit=$rc"
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT/$name.demo.json" \
    || die "$name: DVAA demo did not emit JSON"
}

start_proxy() { # mode
  docker rm -f "$PROXY_NAME" >/dev/null 2>&1 || true
  : > "$WORK/out/proxy-capture.jsonl"
  docker run -d --rm --name "$PROXY_NAME" --network "container:$CONTAINER" \
    -v "$WORK:/s:ro" -v "$WORK/out:/out" \
    -e SENTINEL_MODE="$1" -e SENTINEL_LISTEN_PORT="$PROXY_PORT" \
    -e SENTINEL_TARGET_PORT=7005 -e SENTINEL_CAPTURE_PATH=/out/proxy-capture.jsonl \
    --entrypoint node "$IMAGE" /s/sentinel/proxy/cli.mjs --config /s/contrast.config.json >/dev/null
  for _ in $(seq 1 50); do
    docker exec "$CONTAINER" wget -q -O /dev/null "http://127.0.0.1:$PROXY_PORT/health" 2>/dev/null && return 0
    sleep 0.2
  done
  docker logs "$PROXY_NAME" >&2 || true
  die "SentinelProxy ($1) did not come up on :$PROXY_PORT"
}

stop_proxy() { # name ; keep the proxy's full capture log next to the demo output
  docker stop "$PROXY_NAME" >/dev/null   # SIGTERM -> proxy flushes its sink
  cp "$WORK/out/proxy-capture.jsonl" "$OUT/$1.proxy.jsonl"
}

echo "== T8 contrast against $CONTAINER (SentinelProxy from $SENTINEL_REF @ ${SENTINEL_SHA:0:12}) =="
demo baseline-aim                                   # A: RAGBot 7005   B: RAGBot-AIM 7014 (stock)
demo securebot  DVAA_RAGBOT_AIM_PORT=7001           # A: RAGBot 7005   B: SecureBot 7001
start_proxy block
demo proxy-block DVAA_RAGBOT_AIM_PORT="$PROXY_PORT" # A: RAGBot 7005   B: SentinelProxy(block)  -> 7005
stop_proxy proxy-block
start_proxy observe
demo proxy-observe DVAA_RAGBOT_AIM_PORT="$PROXY_PORT" # A: RAGBot 7005 B: SentinelProxy(observe) -> 7005
stop_proxy proxy-observe

# Inspector label = what the proxy logged (verdict.detector), via the same function build-contrast uses.
INSPECTOR="$(node --input-type=module -e '
  import { inspectorFromLogs, readJsonlBounded } from "'"$HERE"'/build-contrast.mjs";
  const i = inspectorFromLogs(...process.argv.slice(1).map((f) => readJsonlBounded(f)));
  if (!i.label || i.mixed) { console.error(`cannot label inspector: ${JSON.stringify(i)}`); process.exit(1); }
  process.stdout.write(i.label);
' "$OUT/proxy-block.proxy.jsonl" "$OUT/proxy-observe.proxy.jsonl")" || die "could not derive the inspector from the proxy logs"
if [[ "$STANDIN_CFG" == 1 && "$INSPECTOR" != standin-substring ]] || [[ "$STANDIN_CFG" == 0 && "$INSPECTOR" == standin-substring ]]; then
  die "config says stand-in=$STANDIN_CFG but the proxy logged inspector $INSPECTOR"
fi
CFG_SHA="$(sha256_file "$SENTINEL_CONFIG")"

cat > "$OUT/run-meta.json" <<EOF
{
  "dvaa_container": "$CONTAINER",
  "dvaa_image": "$IMAGE",
  "sentinel_ref": "$SENTINEL_REF",
  "sentinel_sha": "$SENTINEL_SHA",
  "inspector": "$INSPECTOR",
  "inspector_source": "verdict.detector in proxy-block.proxy.jsonl + proxy-observe.proxy.jsonl",
  "inspector_config": "$(basename "$SENTINEL_CONFIG")",
  "inspector_config_sha256": "$CFG_SHA",
  "inspector_config_is_standin": $( [[ "$STANDIN_CFG" == 1 ]] && echo true || echo false ),
  "proxy_port_in_dvaa_netns": $PROXY_PORT,
  "captured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

node "$HERE/build-contrast.mjs" "$OUT"
