#!/usr/bin/env bash
# soc-handoff.sh — hand Tourniquet's real alerts to Track 1 SOC Brief, offline.
#
# Usage: scripts/soc-handoff.sh [OUT_DIR]      (default OUT_DIR: .eval/soc-handoff, gitignored)
#
# Inputs are committed stage captures, converted by the real T10 pipeline (sentinel/pipeline):
#   proxy-blocked T3   captures/contrast/runs/proxy-block.t4-alerts.json   (committed T4 sidecar)
#   post-execution     captures/contrast/runs/proxy-observe.proxy.jsonl    (converted here)
#   egress-deny        sentinel/egress/evidence-block.jsonl                (converted here)
# SOC Brief (track1/) briefs them with its deterministic path. No LLM key, no network.
# Output: the brief on stdout and in OUT_DIR/brief.md. Exit non-zero on any failure (fail-loud).
#
# Bash 3.2 safe (macOS default): no associative arrays, no mapfile, no ${var,,}.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$REPO/.eval/soc-handoff}"
NODE="${NODE:-node}"

BLOCK_SIDECAR="$REPO/captures/contrast/runs/proxy-block.t4-alerts.json"
OBSERVE_CAPTURE="$REPO/captures/contrast/runs/proxy-observe.proxy.jsonl"
EGRESS_LOG="$REPO/sentinel/egress/evidence-block.jsonl"

err() { printf '[soc-handoff] ERROR %s\n' "$*" >&2; exit 1; }

command -v "$NODE" >/dev/null 2>&1 || err "node not found (need Node >= 22)"
major="$("$NODE" -p 'process.versions.node.split(".")[0]')"
[ "$major" -ge 22 ] 2>/dev/null || err "Node >= 22 required, found $("$NODE" -v)"
for f in "$BLOCK_SIDECAR" "$OBSERVE_CAPTURE" "$EGRESS_LOG"; do
  [ -f "$f" ] || err "missing input: ${f#$REPO/}"
done

# Offline by construction: SOC Brief only calls a model when given one, and we never give it one.
# Unset the keys anyway so nothing downstream can pick them up.
unset OPENAI_API_KEY LLM_API_KEY LLM_BASE_URL LLM_MODEL || true

mkdir -p "$OUT"
PIPE="$OUT/pipeline"
LOG="$OUT/pipeline.log"
: > "$LOG"

"$NODE" "$REPO/sentinel/pipeline/cli.mjs" convert "$OBSERVE_CAPTURE" --out "$PIPE/observe" --clean >>"$LOG" 2>&1 \
  || err "pipeline convert (observe capture) failed; see ${LOG#$REPO/}"
"$NODE" "$REPO/sentinel/pipeline/cli.mjs" convert --egress "$EGRESS_LOG" --out "$PIPE/egress" --clean >>"$LOG" 2>&1 \
  || err "pipeline convert (egress log) failed; see ${LOG#$REPO/}"

first_json() { # first *.alerts.json in a dir, or fail
  f="$(find "$1" -maxdepth 1 -type f -name '*.alerts.json' | sort | head -n 1)"
  [ -n "$f" ] || err "no alerts sidecar under ${1#$REPO/}"
  printf '%s\n' "$f"
}
OBSERVE_SIDECAR="$(first_json "$PIPE/observe/alerts")"
EGRESS_SIDECAR="$(first_json "$PIPE/egress/alerts")"

"$NODE" "$REPO/scripts/lib/soc-handoff.mjs" \
  --block "$BLOCK_SIDECAR" \
  --observe "$OBSERVE_SIDECAR" \
  --egress "$EGRESS_SIDECAR" \
  --out "$OUT/brief.md"

printf '\n[soc-handoff] wrote %s\n' "${OUT#$REPO/}/brief.md" >&2
