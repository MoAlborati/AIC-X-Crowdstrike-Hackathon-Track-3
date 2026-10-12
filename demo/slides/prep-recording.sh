#!/usr/bin/env bash
# prep-recording.sh — one command to get Catherine's Mac ready to record the fallback video (or to go on stage).
# Follows demo/slides/VIDEO-CHECKLIST.md + demo/PRESENTER.md, with the corrections for this Mac from #124:
# Node 24 at ~/.cache/node24 (brew node@24 is broken here), plain `colima start`, --no-dvaa (no 5-min `up` hang),
# fresh dashboard on committed numbers, stage deep links from PRESENTER.md.
#
#   demo/slides/prep-recording.sh            # prep + dry run, then prints the record steps
#   demo/slides/prep-recording.sh --no-dry   # skip the --auto dry run
set -u
cd "$(dirname "$0")/../.." || exit 1
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILED=1; }
skip() { printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }
FAILED=0
IS_MAC=0; [ "$(uname -s)" = Darwin ] && IS_MAC=1
[ "$IS_MAC" = 1 ] || echo "  note: not macOS ($(uname -s)): Mac-only steps (caffeinate, colima, open) are skipped with a message"

echo "== 1. keep the Mac awake"
if ! command -v caffeinate >/dev/null 2>&1; then skip "caffeinate not found (macOS only): keep this machine awake by hand"
elif pgrep -x caffeinate >/dev/null; then ok "caffeinate already running"
else caffeinate -dimsu >/dev/null 2>&1 & disown; ok "caffeinate started (pid $!)"; fi

echo "== 2. Node 24"
[ -x "$HOME/.cache/node24/bin/node" ] && export PATH="$HOME/.cache/node24/bin:$PATH"
nv=$(node --version 2>/dev/null); nmaj=${nv#v}; nmaj=${nmaj%%.*}
case "$nmaj" in ''|*[!0-9]*) nmaj=0;; esac
if [ "$nmaj" -ge 24 ]; then ok "node $nv"; else bad "node ${nv:-not found} — need >= 24 (expected at ~/.cache/node24/bin)"; fi

echo "== 3. Docker / Colima"
if docker info >/dev/null 2>&1; then ok "docker daemon reachable ($(docker context show))"
elif ! command -v colima >/dev/null 2>&1; then bad "docker not reachable and colima not installed (macOS only): start your Docker daemon by hand"
else echo "  ..    starting colima (30-60 s)"; colima start >/dev/null 2>&1 && docker info >/dev/null 2>&1 && ok "colima started" || bad "docker not reachable: run 'colima start'"; fi

echo "== 4. repo on main, clean"
br=$(git rev-parse --abbrev-ref HEAD); [ "$br" = main ] && ok "on main @ $(git log -1 --format=%h)" || bad "on '$br' — run: git switch main && git pull --ff-only"
[ -z "$(git status --porcelain --untracked-files=no)" ] && ok "no tracked changes" || bad "tracked changes present: git status"

echo "== 5. DVAA fleet"
for i in $(seq 1 12); do curl -fsS -m 2 127.0.0.1:7005/health >/dev/null 2>&1 && curl -fsS -m 2 127.0.0.1:9000/stats >/dev/null 2>&1 && break; sleep 5; done
if curl -fsS -m 2 127.0.0.1:7005/health >/dev/null 2>&1; then ok "DVAA 7005 + 9000 answer"
else bad "DVAA not answering — run: scripts/eval.sh up   (rebuilds from cache, no network)"; fi

echo "== 6. fresh dashboard on the committed numbers"
scripts/eval.sh dashboard-stop >/dev/null 2>&1
rm -rf .eval/score   # so tiles match results.json / the slides, not a fresh rescore
if EVAL_DASHBOARD_PORT=9100 scripts/eval.sh dashboard >/dev/null 2>&1 && curl -fsS -m 3 -o /dev/null 127.0.0.1:9100/; then ok "dashboard on http://127.0.0.1:9100/"
else bad "dashboard did not start: see .eval/dashboard.log"; fi

if [ "${1:-}" != "--no-dry" ]; then
  echo "== 7. dry run (must say 'demo run clean' — do not record until it does)"
  out=$(demo/run-demo.sh --auto --no-dvaa --no-teardown 2>&1)
  if grep -q 'demo run clean' <<<"$out"; then ok "demo run clean"; else bad "dry run not clean:"; grep -E 'FAIL|WARN' <<<"$out" | head -8; fi
  grep -q 'live proxy unavailable' <<<"$out" && bad "Beat 4 fell back to the recording (live proxy unavailable)"
fi

echo "== 8. dashboard tabs (stage view; read from demo/PRESENTER.md so a script cut cannot leave them stale)"
links=$(grep -o 'http://127\.0\.0\.1:9100/?[^` )"]*' demo/PRESENTER.md 2>/dev/null | awk '!seen[$0]++')
if [ -z "$links" ]; then
  links="http://127.0.0.1:9100/?stage=1&capture=vulnerable
http://127.0.0.1:9100/?id=live/proxy-7005&run=run&step=last
http://127.0.0.1:9100/?id=live/egress-boundary&run=run&step=last
http://127.0.0.1:9100/?stage=1&capture=aim-twin"
  echo "  note: no :9100 deep links found in demo/PRESENTER.md; using the built-in four"
fi
n=0
while IFS= read -r u; do
  [ -n "$u" ] || continue; n=$((n+1))
  if [ "$IS_MAC" = 1 ]; then open "$u"; else echo "        $u"; fi
done <<EOF
$links
EOF
if [ "$IS_MAC" = 1 ]; then ok "opened $n tabs in the default browser (in PRESENTER.md order)"
else skip "'open' is macOS only: open the $n links above by hand"; fi

echo
if [ "$FAILED" -ne 0 ]; then printf '\033[31mNOT READY\033[0m — fix the FAIL lines above, then rerun.\n'; exit 1; fi
cat <<'EOF'
READY. Now, by hand:
  - Do Not Disturb on; quit Slack/Mail/Messages; Dock auto-hide; bookmarks bar hidden (Cmd-Shift-B)
  - Terminal: 18pt, full height, left half · browser right half · slides one Cmd-Tab away
  - In the demo terminal:   export PS1='$ '; export PATH="$HOME/.cache/node24/bin:$PATH"; clear
  - Start the run:          demo/run-demo.sh --no-dvaa --no-teardown
    press Enter through ALL THREE preflights; park at the prompt after "Preflight 3/3"; then Cmd-K
  - Cmd-Shift-5 → Record Selected Portion · Microphone None · Show Mouse Clicks On · Floating Thumbnail Off · Save to Desktop
  - Cmd-K before every Enter so each beat starts at the top
  - Stop with Cmd-Ctrl-Esc · rename to ~/Desktop/fallback-demo-raw.mov · trim per VIDEO-CHECKLIST §5
  - NEVER save the .mov inside the repo (*.mov is not gitignored)
EOF
