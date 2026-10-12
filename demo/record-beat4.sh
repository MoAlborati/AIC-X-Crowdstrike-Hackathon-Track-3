#!/usr/bin/env bash
# demo/record-beat4.sh — re-record the Beat 4 evidence with the SHIPPED proxy CLI.
#
# What it records: RAGBot 7005 behind SentinelProxy in BLOCK mode, started exactly as shipped:
#   node sentinel/proxy/cli.mjs --config sentinel/config/sentinel.config.json
# The CLI registers [substring, sentinel-t3] (PR #41). The shipped config has an empty
# inspect.flagSubstrings, so no stand-in needles are added. The poisoned-document request is sent by
# DVAA's own `demo aim-ab` runner (run B pointed at the proxy). We write no attack content.
#
# The proxy code is the exact tree at SENTINEL_REF (default origin/main), extracted with git archive.
# It runs in a throwaway container that shares the DVAA container's network namespace, the same way
# as captures/contrast/run-contrast.sh. This is a defensive, authorized hackathon demo against the
# organizers' localhost DVAA sandbox only.
#
# Output (default demo/captures/):
#   beat4-proxy-block.proxy.jsonl   the proxy's full capture log (exchanges + alerts)
#   beat4-proxy-block.demo.json     DVAA's runner output (run A = vulnerable positive control)
#   beat4-meta.json                 ref/sha, config, and the detector(s) the proxy actually logged
#
# Usage: demo/record-beat4.sh [OUT_DIR]
# Env:   DVAA_CONTAINER (dvaa-t1-dvaa-1)  DVAA_IMAGE (dvaa-t1-dvaa)  SENTINEL_REF (origin/main)
#        PROXY_PORT (7099, inside the DVAA netns)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER="${DVAA_CONTAINER:-dvaa-t1-dvaa-1}"
IMAGE="${DVAA_IMAGE:-dvaa-t1-dvaa}"
SENTINEL_REF="${SENTINEL_REF:-origin/main}"
PROXY_PORT="${PROXY_PORT:-7099}"
CONFIG_REL="sentinel/config/sentinel.config.json"
OUT="$(mkdir -p "${1:-$REPO/demo/captures}" && cd "${1:-$REPO/demo/captures}" && pwd)"
PROXY_NAME="t9-beat4-proxy-$$"

die() { echo "record-beat4: ERROR: $*" >&2; exit 1; }

git -C "$REPO" rev-parse --verify --quiet "$SENTINEL_REF" >/dev/null || die "unknown SENTINEL_REF $SENTINEL_REF"
SENTINEL_SHA="$(git -C "$REPO" rev-parse "$SENTINEL_REF")"
docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true || die "DVAA container $CONTAINER is not running"
curl -sf --max-time 3 "http://127.0.0.1:7005/health" >/dev/null || die "RAGBot 7005 is not healthy"

WORK="$(mktemp -d)"
cleanup() { docker rm -f "$PROXY_NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
# sentinel/detectors is required: the shipped CLI imports T3 through default-inspectors.mjs.
git -C "$REPO" archive "$SENTINEL_REF" sentinel/proxy sentinel/config sentinel/alerts sentinel/detectors | tar -x -C "$WORK"
mkdir -p "$WORK/out" && chmod 777 "$WORK/out"
: > "$WORK/out/proxy-capture.jsonl"

docker run -d --rm --name "$PROXY_NAME" --network "container:$CONTAINER" \
  -v "$WORK:/s:ro" -v "$WORK/out:/out" \
  -e SENTINEL_MODE=block -e SENTINEL_LISTEN_PORT="$PROXY_PORT" \
  -e SENTINEL_TARGET_PORT=7005 -e SENTINEL_CAPTURE_PATH=/out/proxy-capture.jsonl \
  --entrypoint node "$IMAGE" /s/sentinel/proxy/cli.mjs --config "/s/$CONFIG_REL" >/dev/null
up=0
for _ in $(seq 1 50); do
  docker exec "$CONTAINER" wget -q -O /dev/null "http://127.0.0.1:$PROXY_PORT/health" 2>/dev/null && { up=1; break; }
  sleep 0.2
done
[ "$up" = 1 ] || { docker logs "$PROXY_NAME" >&2 || true; die "SentinelProxy did not come up on :$PROXY_PORT"; }
LISTEN_LINE="$(docker logs "$PROXY_NAME" 2>/dev/null | head -1)"

set +e
docker exec -e DVAA_BASE=http://127.0.0.1 -e DVAA_RAGBOT_AIM_PORT="$PROXY_PORT" "$CONTAINER" \
  node src/index.js demo aim-ab --json > "$OUT/beat4-proxy-block.demo.json"
rc=$?
set -e
echo "  dvaa demo exit=$rc (run B is not an AIM agent, so exit 1 is expected)"
docker stop "$PROXY_NAME" >/dev/null   # SIGTERM -> proxy flushes its sink
cp "$WORK/out/proxy-capture.jsonl" "$OUT/beat4-proxy-block.proxy.jsonl"

# The credit is derived from what the proxy logged on the blocked exchange, never assumed.
DETECTORS="$(jq -rc '[select(.type=="exchange" and ((.action//"")|test("block"))) | .verdicts[]? | select(.flagged==true) | .detector] | unique' \
  "$OUT/beat4-proxy-block.proxy.jsonl" | jq -sc 'add | unique')"
[ "$DETECTORS" != "[]" ] && [ "$DETECTORS" != "null" ] || die "no flagged verdict on a blocked exchange; nothing to credit"
jq -e '.runA.dvaa.exfilExecuted == true' "$OUT/beat4-proxy-block.demo.json" >/dev/null \
  || die "run A (vulnerable RAGBot, direct) did not execute the exfil: no positive control"

cat > "$OUT/beat4-meta.json" <<EOF
{
  "sentinel_ref": "$SENTINEL_REF",
  "sentinel_sha": "$SENTINEL_SHA",
  "proxy_command": "node sentinel/proxy/cli.mjs --config $CONFIG_REL",
  "proxy_listening": $LISTEN_LINE,
  "mode": "block",
  "target": "127.0.0.1:7005 (RAGBot)",
  "request_source": "DVAA demo aim-ab run B via DVAA_RAGBOT_AIM_PORT=$PROXY_PORT",
  "blocking_detectors": $DETECTORS,
  "blocking_detectors_source": "flagged verdicts on blocked exchanges in beat4-proxy-block.proxy.jsonl",
  "dvaa_container": "$CONTAINER",
  "captured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
echo "  blocking detector(s): $DETECTORS"
echo "  wrote $OUT/beat4-proxy-block.{proxy.jsonl,demo.json} + beat4-meta.json"
