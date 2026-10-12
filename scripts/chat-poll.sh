#!/usr/bin/env bash
# chat-poll.sh — GitHub Issues chat intake poller for the orchestrator (see CHAT.md).
#
# Prints one line per unanswered message in any open issue:
#   CHAT_EVENT prio=<URGENT|normal> issue=#<n> from=<login> key=<n:cid|n:body> title=<title>
# A thread counts as answered once its newest item (the issue body, or the last comment) contains the
# orchestrator reply marker <!-- orchestrator-reply -->. Issues labelled `chat-urgent`, or opened from the
# chat form with the "Urgent" box ticked, print prio=URGENT.
#
# Env knobs:
#   CHAT_REPO      owner/repo to poll (default: this repo)
#   CHAT_INTERVAL  seconds between polls (default: 15)
#   CHAT_STATE_DIR where seen-message keys are stored (default: <repo>/.chat, gitignored)
#
# Bounds: open issues and comments are fetched with --paginate, so no thread or message is dropped
# however many there are (no capped list scan). A failed API call is reported on stderr, never skipped silently.
set -uo pipefail

REPO="${CHAT_REPO:-shrutidoshi94/AIC-X-Crowdstrike-Hackathon-Track-3}"
INTERVAL="${CHAT_INTERVAL:-15}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${CHAT_STATE_DIR:-$ROOT/.chat}"
STATE="$STATE_DIR/seen.txt"
# Reply marker (documented in CHAT.md): <!-- orchestrator-reply -->
mkdir -p "$STATE_DIR" && touch "$STATE"

err() { echo "chat-poll: $*" >&2; }

while true; do
  if ! issues=$(gh api --paginate "repos/$REPO/issues?state=open&per_page=100&sort=updated" \
      --jq '.[] | select(.pull_request|not) | "\(.number)\t\([.labels[].name] + (if ((.body // "") | test("- \\[[xX]\\] Urgent")) then ["chat-urgent"] else [] end) | join(","))\t\(.title)"'); then
    err "listing issues for $REPO failed; retrying in ${INTERVAL}s"; sleep "$INTERVAL"; continue
  fi
  while IFS=$'\t' read -r n labels title; do
    [ -z "$n" ] && continue
    # The marker is a jq literal because `gh api --jq` has no --arg; keep it in sync with the marker noted above.
    if ! all=$(gh api --paginate "repos/$REPO/issues/$n/comments?per_page=100" \
        --jq '.[] | "\(.id)\t\((.body // "") | contains("<!-- orchestrator-reply -->"))\t\(.user.login)"'); then
      err "reading comments of #$n failed"; continue
    fi
    last=$(printf '%s\n' "$all" | sed '/^$/d' | tail -n1)
    if [ -z "$last" ]; then
      if ! meta=$(gh api "repos/$REPO/issues/$n" \
          --jq '"\((.body // "") | contains("<!-- orchestrator-reply -->"))\t\(.user.login)"'); then
        err "reading #$n failed"; continue
      fi
      IFS=$'\t' read -r marked who <<<"$meta"; key="$n:body"
    else
      IFS=$'\t' read -r cid marked who <<<"$last"; key="$n:$cid"
    fi
    if [ "$marked" = "false" ] && ! grep -qxF "$key" "$STATE"; then
      echo "$key" >> "$STATE"
      prio=normal; [[ ",$labels," == *",chat-urgent,"* ]] && prio=URGENT
      echo "CHAT_EVENT prio=$prio issue=#$n from=$who key=$key title=$title"
    fi
  done <<<"$issues"
  sleep "$INTERVAL"
done
