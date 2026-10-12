#!/usr/bin/env bash
# chat-poll.sh — GitHub Issues chat intake poller for the orchestrator (see CHAT.md).
#
# Prints one line per unanswered message:
#   CHAT_EVENT prio=<URGENT|normal> issue=#<n> from=<login> key=<n:cid|n:body> title=<title>
# and one line per stale thread:
#   CHAT_EVENT prio=STALE issue=#<n> from=<login> key=<n:stale> title=<title>
#
# Unanswered: the newest item (the last comment, or the issue body if there are no comments) lacks the
# orchestrator reply marker <!-- orchestrator-reply -->. Agents post with the marker, so anything without
# it, from anyone, is a message to handle. Scanned on every OPEN issue and on every CLOSED issue updated in
# the last CHAT_CLOSED_WINDOW seconds (default 6h): humans also comment on closed issues (e.g. #72, #54).
# A closed issue with no comments is not an event (closing it was the answer).
# Issues labelled `chat-urgent`, or opened from the chat form with the "Urgent" box ticked, print prio=URGENT.
#
# Stale: an OPEN issue labelled `needs-human`, or with a deadline in its title, whose last
# orchestrator-reply comment (or, with none, its creation) is CHAT_STALE_AFTER seconds old or more
# (default 1800). Emitted at most once per issue per CHAT_STALE_AFTER seconds.
#
# Startup: the seen/stale state is reset, so every item that is unanswered (or stale) right now is emitted
# on the first poll, including ones a previous run already printed. Nothing is silently marked seen.
#
# Env knobs:
#   CHAT_REPO           owner/repo to poll (default: this repo)
#   CHAT_INTERVAL       seconds between polls (default 30, floor 30)
#   CHAT_STATE_DIR      where seen-message keys are stored (default: <repo>/.chat, gitignored)
#   CHAT_CLOSED_WINDOW  how far back closed issues are scanned, seconds (default 21600 = 6h)
#   CHAT_STALE_AFTER    stale threshold and STALE re-emit period, seconds (default 1800)
#   CHAT_MAX_POLLS      stop after this many polls (default 0 = forever; used by tests)
#   CHAT_NOW, CHAT_NOW_STEP  test clock: epoch of the first poll, and seconds added per poll
#
# Bounds: issues and comments are fetched with --paginate, so no thread or message is dropped however many
# there are (no capped list scan). Rate limit: an issue's comments are re-fetched only when its updated_at or
# comment count changed since the last poll (cached in CHAT_STATE_DIR/comments-<n>.txt); otherwise ~48 issues
# x 120 polls/h would exceed GitHub's 5000/h core limit that gh merges and gates share. Rows without a
# numeric comment count are never cached. The closed-issue window is a time bound, not a count bound.
# A failed API call is reported on stderr, never skipped silently.
# Bash 3.2 compatible (no mapfile, no associative arrays).
set -uo pipefail

REPO="${CHAT_REPO:-shrutidoshi94/AIC-X-Crowdstrike-Hackathon-Track-3}"
INTERVAL="${CHAT_INTERVAL:-30}"
case "$INTERVAL" in ''|*[!0-9]*) INTERVAL=30 ;; esac
[ "$INTERVAL" -lt 30 ] && INTERVAL=30
CLOSED_WINDOW="${CHAT_CLOSED_WINDOW:-21600}"
STALE_AFTER="${CHAT_STALE_AFTER:-1800}"
MAX_POLLS="${CHAT_MAX_POLLS:-0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${CHAT_STATE_DIR:-$ROOT/.chat}"
STATE="$STATE_DIR/seen.txt"
STALE_STATE="$STATE_DIR/stale.txt"
# Reply marker (documented in CHAT.md): <!-- orchestrator-reply -->
mkdir -p "$STATE_DIR"
# Startup: forget what earlier runs printed, so currently unanswered items are emitted again.
: > "$STATE"; : > "$STALE_STATE"; rm -f "$STATE_DIR"/comments-*.txt

# Field separator for jq rows: ASCII unit separator, not tab. Tab is IFS whitespace, so `read` would merge an
# empty field (an issue with no labels) into the next one and shift every field after it.
US=$'\037'

err() { echo "chat-poll: $*" >&2; }

iso_utc() { # epoch -> YYYY-MM-DDTHH:MM:SSZ (GNU date, then BSD date)
  date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ
}

# One issue row per line (US-separated): number, state, labels (+chat-urgent if the form box is ticked), created epoch, title.
# The marker is a jq literal because `gh api --jq` has no --arg; keep it in sync with the marker noted above.
ISSUE_JQ='.[] | select(.pull_request|not) | "\(.number)\u001f\(.state)\u001f\([.labels[].name] + (if ((.body // "") | test("- \\[[xX]\\] Urgent")) then ["chat-urgent"] else [] end) | join(","))\u001f\(.created_at | fromdateiso8601)\u001f\(.updated_at)/\(.comments)\u001f\(.title)"'
COMMENT_JQ='.[] | "\(.id)\u001f\((.body // "") | contains("<!-- orchestrator-reply -->"))\u001f\(.user.login)\u001f\(.created_at | fromdateiso8601)"'

handle_issue() { # n state labels created ver title
  local n="$1" state="$2" labels="$3" created="$4" ver="$5" title="$6"
  local all last cid marked who key meta prio lastreply prev cache="$STATE_DIR/comments-$n.txt"
  if [ -f "$cache" ] && [ "$(head -n1 "$cache")" = "v=$ver" ] && case "$ver" in */null|'') false ;; esac; then
    all=$(tail -n +2 "$cache")   # unchanged since last poll (same updated_at + comment count): reuse
  else
    if ! all=$(gh api --paginate "repos/$REPO/issues/$n/comments?per_page=100" --jq "$COMMENT_JQ"); then
      err "reading comments of #$n failed"; return
    fi
    all=$(printf '%s\n' "$all" | sed '/^$/d')
    { printf 'v=%s\n' "$ver"; printf '%s\n' "$all"; } > "$cache"
  fi
  last=$(printf '%s\n' "$all" | tail -n1)
  if [ -z "$last" ]; then
    [ "$state" = closed ] && return   # closed with no comments: nothing to answer
    if ! meta=$(gh api "repos/$REPO/issues/$n" \
        --jq '"\((.body // "") | contains("<!-- orchestrator-reply -->"))\u001f\(.user.login)"'); then
      err "reading #$n failed"; return
    fi
    IFS="$US" read -r marked who <<<"$meta"; key="$n:body"
  else
    IFS="$US" read -r cid marked who _ <<<"$last"; key="$n:$cid"
  fi
  if [ "$marked" = "false" ] && ! grep -qxF "$key" "$STATE"; then
    echo "$key" >> "$STATE"
    prio=normal; [[ ",$labels," == *",chat-urgent,"* ]] && prio=URGENT
    echo "CHAT_EVENT prio=$prio issue=#$n from=$who key=$key title=$title"
  fi

  # STALE: open needs-human / deadline issues with no orchestrator reply for STALE_AFTER seconds.
  [ "$state" = open ] || return
  if [[ ",$labels," != *",needs-human,"* ]] && \
     ! printf '%s' "$title" | grep -qiE 'deadline|due[[:space:]]+(by|at)|by[[:space:]]+[0-9]{1,2}:[0-9]{2}'; then
    return
  fi
  lastreply=$(printf '%s\n' "$all" | awk -F"$US" '$2=="true" && $4>m {m=$4} END {print m+0}')
  [ "$lastreply" -gt 0 ] || lastreply="$created"
  [ $((NOW - lastreply)) -ge "$STALE_AFTER" ] || return
  prev=$(awk -v n="$n" '$1==n {p=$2} END {print p+0}' "$STALE_STATE")
  if [ "$prev" -eq 0 ] || [ $((NOW - prev)) -ge "$STALE_AFTER" ]; then
    echo "$n $NOW" >> "$STALE_STATE"
    echo "CHAT_EVENT prio=STALE issue=#$n from=${who:-?} key=$n:stale title=$title"
  fi
}

poll() {
  local issues closed since n state labels created ver title
  if ! issues=$(gh api --paginate "repos/$REPO/issues?state=open&per_page=100&sort=updated" --jq "$ISSUE_JQ"); then
    err "listing open issues for $REPO failed"; issues=""
  fi
  since=$(iso_utc $((NOW - CLOSED_WINDOW)))
  if ! closed=$(gh api --paginate "repos/$REPO/issues?state=closed&since=$since&per_page=100&sort=updated" --jq "$ISSUE_JQ"); then
    err "listing closed issues for $REPO failed"; closed=""
  fi
  while IFS="$US" read -r n state labels created ver title; do
    [ -z "$n" ] && continue
    handle_issue "$n" "$state" "$labels" "$created" "$ver" "$title"
  done <<<"$(printf '%s\n%s\n' "$issues" "$closed")"
}

polls=0
while true; do
  if [ -n "${CHAT_NOW:-}" ]; then NOW=$((CHAT_NOW + polls * ${CHAT_NOW_STEP:-0})); else NOW=$(date +%s); fi
  poll
  polls=$((polls + 1))
  [ "$MAX_POLLS" -gt 0 ] && [ "$polls" -ge "$MAX_POLLS" ] && break
  sleep "$INTERVAL"
done
