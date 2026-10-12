#!/usr/bin/env bash
# stage-egress-capture.sh — regenerate stage capture 4 (sentinel/dashboard/stage/egress-blocked-t12.json)
# from a REAL `scripts/egress-demo.sh block` run, on a unique compose project + subnet so it never collides
# with a running delivery gate or another egress demo.
#
#   scripts/stage-egress-capture.sh [out.json]
#   env: EGRESS_PROJECT / EGRESS_NET override the generated unique values; DVAA_IMAGE as for egress-demo.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export EGRESS_PROJECT="${EGRESS_PROJECT:-sentinel-egress-stage-$$}"
export EGRESS_NET="${EGRESS_NET:-10.231.$(( 200 + $$ % 50 ))}"
export EGRESS_LOG_DIR="$WORK/logs"
export EGRESS_TURN_LOG="$WORK/turns.jsonl"
echo "stage-egress: project $EGRESS_PROJECT, net $EGRESS_NET.0/24"
bash "$ROOT/scripts/egress-demo.sh" block | tee "$WORK/egress-block.log"
node "$ROOT/sentinel/pipeline/cli.mjs" convert --egress "$EGRESS_LOG_DIR/egress.jsonl" --out "$WORK/out" --clean >/dev/null
node "$ROOT/sentinel/dashboard/fixtures/make-egress-stage.mjs" "$WORK/out" "$WORK/egress-block.log" "$EGRESS_TURN_LOG" "$@"
