#!/usr/bin/env bash
# serve-deck.sh: serve the live deck from the repo root on loopback only, print the URL and open it (macOS).
#
# Usage: demo/slides/serve-deck.sh [--no-open]
#   DECK_PORT=8765 (default)   port to bind on 127.0.0.1
#
# The deck fetches the repo's committed result files by relative path, so the server root must be the repo root.
# Bash 3.2 safe (macOS default): no associative arrays, no mapfile, no ${var,,}. Ctrl-C stops the server.
set -eu

PORT="${DECK_PORT:-8765}"
OPEN=1
for arg in "$@"; do
  case "$arg" in
    --no-open) OPEN=0 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "serve-deck: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

case "$PORT" in
  ''|*[!0-9]*) echo "serve-deck: DECK_PORT must be a number (got '$PORT')" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
URL="http://127.0.0.1:${PORT}/demo/slides/deck.html"

if ! command -v python3 >/dev/null 2>&1; then
  echo "serve-deck: python3 not found (install the Xcode command line tools: xcode-select --install)" >&2
  exit 3
fi

if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "serve-deck: port $PORT is already in use. Pick another: DECK_PORT=8766 $0" >&2
  exit 4
fi

cd "$ROOT"
python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
PID=$!
cleanup() { kill "$PID" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

# Wait (up to ~5 s) for the server to answer.
i=0
while [ "$i" -lt 50 ]; do
  if curl -fsS -o /dev/null "$URL" 2>/dev/null; then break; fi
  if ! kill -0 "$PID" 2>/dev/null; then echo "serve-deck: server exited early" >&2; exit 5; fi
  sleep 0.1
  i=$((i + 1))
done

echo "Deck:    $URL"
echo "Serving: $ROOT (127.0.0.1 only). Ctrl-C to stop."
echo "Keys:    arrows/space/Home/End · N notes + clock · F fullscreen · S sources · P presenter window"

if [ "$OPEN" -eq 1 ] && command -v open >/dev/null 2>&1; then
  open "$URL" || true
fi

wait "$PID"
