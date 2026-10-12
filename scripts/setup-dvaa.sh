#!/usr/bin/env bash
# setup-dvaa.sh — bring up the DVAA training target (localhost only).
#
# DVAA ("Damn Vulnerable AI Agent") is the organizer-provided, intentionally
# vulnerable training sandbox for the CrowdStrike x SCU hackathon (Track 3).
# It runs ONLY on localhost. SentinelProxy is a purely defensive detector that
# consumes DVAA's behavior; we do not attack any real system.
#
# This script clones DVAA at a PINNED commit and runs it via its own
# docker-compose.yml, which already binds every published port to 127.0.0.1.
# The local Node is v22 but DVAA requires Node >=24, so Docker is the supported
# path on this machine (Dockerfile pins node:24-alpine by digest).
#
# Usage:
#   scripts/setup-dvaa.sh clone   # clone/checkout the pinned source only (no Docker); used by the
#                                 # T6 corpus tests' real-DVAA seam (captures/variants/tools/baseline.mjs
#                                 # finds it at $DVAA_DIR, default ${TMPDIR:-/tmp}/dvaa-target)
#   scripts/setup-dvaa.sh up      # clone (if needed), build, start, health-check
#   scripts/setup-dvaa.sh down    # stop + remove the fleet
#   scripts/setup-dvaa.sh health  # health-check the running fleet
set -euo pipefail

DVAA_REPO="${DVAA_REPO:-https://github.com/opena2a-org/damn-vulnerable-ai-agent.git}"
# v0.9.3 — "21 agents, 12 vulnerability categories". Pin for reproducibility.
DVAA_PIN="${DVAA_PIN:-57918267d8d529ceec6d40fc9836ab09d128eee4}"
DVAA_DIR="${DVAA_DIR:-${TMPDIR:-/tmp}/dvaa-target}"
PROJECT="${DVAA_PROJECT:-dvaa-t1}"
IMAGE_TAG="${PROJECT}-dvaa"

# All API agent ports + dashboard. Container binds 0.0.0.0 internally; compose
# publishes each to 127.0.0.1 only.
API_PORTS=(7001 7002 7003 7004 7005 7006 7007 7008 7014 7015 7016 7017 7018 7022 7023)
MCP_PORTS=(7010 7011 7012 7013)
A2A_PORTS=(7020 7021)
DASH=9000

clone() {
  if [ ! -d "$DVAA_DIR/.git" ]; then
    git clone "$DVAA_REPO" "$DVAA_DIR"
  fi
  git -C "$DVAA_DIR" fetch --all --tags
  git -C "$DVAA_DIR" checkout "$DVAA_PIN"
  echo "DVAA checked out at $(git -C "$DVAA_DIR" rev-parse --short HEAD)"
  echo "Corpus tests: DVAA_SRC=$DVAA_DIR DVAA_REQUIRE_REAL=1 node --test captures/variants/tests/*.test.mjs"
}

up() {
  clone
  # docker-compose.yml already maps 127.0.0.1:<port>:<port> for every agent.
  docker compose -p "$PROJECT" -f "$DVAA_DIR/docker-compose.yml" up -d --build
  echo "Waiting for dashboard :$DASH ..."
  for _ in $(seq 1 45); do
    if curl -fsS --max-time 2 "http://127.0.0.1:$DASH/stats" >/dev/null 2>&1; then break; fi
    sleep 5
  done
  health
}

health() {
  echo "== dashboard :$DASH =="
  for ep in /health /stats /api/attack-log; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$DASH$ep" || echo ERR)
    echo "  $ep -> $code"
  done
  echo "== agent ports (/health) =="
  for p in "${API_PORTS[@]}" "${MCP_PORTS[@]}" "${A2A_PORTS[@]}"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$p/health" || echo ERR)
    echo "  $p -> $code"
  done
}

down() {
  docker compose -p "$PROJECT" -f "$DVAA_DIR/docker-compose.yml" down
}

case "${1:-up}" in
  clone) clone ;;
  up) up ;;
  down) down ;;
  health) health ;;
  *) echo "usage: $0 {clone|up|down|health}" >&2; exit 2 ;;
esac
