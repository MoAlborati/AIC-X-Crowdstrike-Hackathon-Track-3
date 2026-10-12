# PRESENTER — 18:00 run-of-show (Catherine, Mac, screen share)

One page. Follow it top to bottom. **Hard stop at 3:00, and don't debug on stage: switch to the fallback.**
Every quoted line below is copied word for word from `demo/SCRIPT.md`. The Beat 3–7 lines are also the `say`
lines of `demo/run-demo.sh`, which prints each one in cyan, and `demo/run-demo.sh --check-script` fails if they drift.
If you need to shorten a line, drop sentences from it. Don't reword it.
Judge answers: [`demo/QA-PREP.md`](QA-PREP.md). Read it once before 18:00.
All commands run from the repo root. Under Colima the repo must be somewhere under `~`, because Colima only shares `$HOME`.

> **If #76 (`t5-stage`) is not merged:** there is no `?stage=1` and no `?capture=`. Open these tabs instead:
> `http://127.0.0.1:9100/?id=attack/aim-ab.demo&run=runA` (vulnerable) and `…&run=runB` (AIM twin). For the
> proxy-blocked view, stay on the terminal; Beat 4 prints the block and the T4 alert there. There is also no
> **Copy alert JSON** button.

## T-30 min checklist

- [ ] `colima start --cpu 4 --memory 6`, then confirm with `docker info | head -3`.
- [ ] `export PATH=/opt/homebrew/opt/node@24/bin:$PATH`, then confirm that `node --version` prints `v24.x`.
- [ ] `git pull`, then `scripts/eval.sh doctor`. Expect all PASS. Every FAIL prints its macOS `fix:` line.
- [ ] `scripts/eval.sh up`. Expect `all 22 DVAA ports answer 200` and `bound to 127.0.0.1`.
- [ ] Pre-warm the dashboard on a fixed port with `EVAL_DASHBOARD_PORT=9100 scripts/eval.sh dashboard`, then open three tabs:
      `http://127.0.0.1:9100/?stage=1&capture=vulnerable`, `…?stage=1&capture=aim-twin`, and
      `…?stage=1&capture=proxy-blocked&step=last`.
- [ ] Dry run: `demo/run-demo.sh --auto --keep-dvaa --no-teardown`. The Summary must say `demo run clean`,
      and Beat 4 must show a **live** `200` then `403`, with no `WARN live proxy unavailable`.
- [ ] Have the fallback video open in QuickTime, paused at 0:00 (`~/Desktop/fallback-demo.mov`; see **After**).
- [ ] Quit Slack, Mail, Messages and anything else that pops up. Turn on **Do Not Disturb** (Control Center → Focus).
- [ ] Screen share: set the display to 1920×1080 or the "Default" scaling (System Settings → Displays). Share the
      whole screen, not one window, so you can switch between the terminal, the browser and the slides.
- [ ] Terminal: Cmd-+ until the font is at least 20pt, dark theme. Put the terminal on the left and the dashboard on the right.
- [ ] At T-2, run `demo/run-demo.sh --keep-dvaa --no-teardown` (interactive). Let the preflights pass (row 0 is the
      script-drift check), then **stop at the first "press Enter"**, before Beat 3. That's your starting position.

> **Beat 4b dashboard view, if available** (branch `stage-egress`, not on main yet): it adds a **4th stage capture**,
> the tool-boundary egress block, to the `?stage=1` dropdown. If it has merged by T-30, open it in a fourth tab and show
> it during Beat 4b. If not, Beat 4b is terminal-only, which is what main does today.

## Run of show (3:00 clock; Enter advances each beat)

Main runs the beats in this order: 1 → 2 → **3 → 3b → 4 → 4b → 5a** → 6 → **7**. Beats 1, 2 and 6 are slides only;
`run-demo.sh` drives the beats in bold.

**0:00 · Beat 1 Hook** · slide 1 → 2 (two incidents + the Kurtz quote) · fallback: keep talking
> "Air Canada lost a tribunal case over its chatbot. A Chevy dealer's chatbot 'agreed' to sell a 2024
> Tahoe for $1. CrowdStrike's CEO put it plainly: 'Each prompt becomes an entry point for the
> adversary.' Today that prompt can arrive inside a document your agent reads."

**0:20 · Beat 2 Structure** · slide 3 (confused-deputy diagram)
> "Picture a new bank teller who obeys any note slipped into a deposit envelope. The teller has the
> authority, the customer owns it, and the attacker can't touch the vault directly, so the attacker
> writes the note. That's the confused deputy, Hardy 1988. Your AI agent is that teller, and every RAG doc,
> web page and repo file is an envelope."

**0:40 · Beat 3 Exploit (red)** · **Enter**, then the dashboard tab `vulnerable` · fallback: play the video from 0:40
> "This is RAGBot on port 7005, an intentionally vulnerable agent from the organizers' DVAA sandbox."
> "We send it one request carrying poisoned retrieved content, the client-side RAG pattern, taken from DVAA's own attack corpus."

Screen: `submit_to_index`, `true`, `… dvaa-admin-secret | … 123-45-6789` (fake sandbox values).
> "It called submit_to_index, and the admin secret and an SSN just left the building."

Pause for two seconds and let it land.

**1:00 · Beat 3b 8KB evasion (red, DoD item 1, never cut)** · **Enter** · fallback: read the lines from the slide
> "DVAA's own scanner only looks at the first and last 8KB. This one hides in the middle, so the scanner sees nothing."

Screen: `inMiddleGap:true`, `evadesDvaaBaseline:true`, `fullScanFindsSignal:true`, then `t3Caught: 2`.
> "SentinelProxy scans the full payload and never truncates. 8KB evasion: 2 out of 2 fixtures caught."

**1:20 · Beat 4 Detect → alert → block (green, live)** · **Enter**, then the dashboard tab `proxy-blocked`.
`run-demo.sh` starts the real shipped proxy (`sentinel/proxy/cli.mjs`, block mode, `sentinel-t3`) on an ephemeral
loopback port in front of 7005 and sends two `curl`s to it.
> "Same agent, same request, but now it goes through SentinelProxy. First, a normal question passes untouched."

Screen: live `200`.
> "Now the attack."

Screen: live `403`, `blocked_request`, `detector: sentinel-t3`, then the recording and the T4 alert
(`IndirectPromptInjection`, ATLAS AML.T0051.001, OWASP LLM01, ASI01, OASB-1, Blocked).
> "Blocked at the request boundary, before it was ever forwarded to the model. The verdict comes from our T3 detector, sentinel-t3, with reason codes exfil_instruction_inbound, injection_markers, payee_not_confirmed. Prevention is request-side. If a honeytoken shows up in a response instead, the tool already ran (alert-only for prevention), but in block mode the reply is withheld, so the secret never reaches the client."

> "Nothing was forwarded, so nothing could be exfiltrated."

Fallback is automatic. If the terminal prints `WARN live proxy unavailable; showing the recording`, keep going (see **If X breaks**).

**1:40 · Beat 4b Egress guard (green, tool boundary)** · **Enter** · fallback: read `PREVENTED` and move on
> "When a request-side block is not the control, like RepoBot, which reads its payload inside the agent so the proxy cannot stop the exfil, the egress guard is what stops it. It denies non-allowlisted destinations and honeytokens, and fails closed."

Screen: `deny` rows (RAGBot 7005 honeytokens, RepoBot 7022 `bootstrap.sh` fetch + credential post), then
`RESULT block: PREVENTED`, `RESULT repobot block: PREVENTED`, `(no canary hits)`. If the 4th stage capture is
available (see the box above), switch to it here.
> "The api.oa2a.org deny is DVAA's startup telemetry, blocked by the allowlist."

**1:50 · Beat 5a AIM twin** · **Enter**, then the tab `aim-twin`, then slide 6 (red / green / green) · fallback: slide 6 only
> "Its twin, RAGBot-AIM 7014, is the same code with its capability guard switched on, and it is denied."

Screen: `false` + the AIM denial reason.
> "Secure-by-design works when you can rebuild the agent. We protect the agents you can't rebuild."

**2:05 · Beat 6 How it works** · slide 7 (field → mechanism → rule) · if you're running long, keep only two mechanisms
> "We didn't invent these controls. We borrowed them from fields that already solved the confused deputy.
> Banks check the payee before money moves, so we block any destination that came only from untrusted content.
> Power of attorney is limited by what the principal granted, so the user's own turn sets the mandate and a document
> can't widen it. And a dead-man switch fails closed: if our scanner times out or the input is too big, egress is
> denied and we raise an alert. We scan the full payload and never truncate it."

**2:30 · Beat 7 Close** · **Enter**, then slides 8 → 10 · fallback: read the numbers off the slide

The terminal prints the T3 vs DVAA table: recall, FP, `8KB evasion: 2/2`, p95 0.4 ms.
> "Scored against DVAA's own ground-truth labels on 189 attacks and 164 benign runs. On this corpus DVAA's baseline has the higher recall, and it pays for it in false positives: it flags 12.8 percent of benign traffic, and T3 flags none. 8KB evasion: 2 out of 2 fixtures. In-detector latency is under half a millisecond."

> "This is a working slice of Falcon AI Detection and Response, at the tool boundary. Thank you."

Running long? Cut the benign pass in Beat 4 first, then trim Beat 6. **Never cut 3b.**

## Claim wording (for Q&A; also see `demo/QA-PREP.md`)

- **Scope the FP claim every time:** "0% FP on the 164-case benign corpus." Never say "zero false positives" without that scope.
- **The recall one-liner:** "We now detect slightly more than DVAA's baseline, but it prevents more, at a 12.8% benign FP rate. We have 0 FP on the 164-case benign corpus, and we catch the 2 cases that evade its 8KB window."
- **Held-out FP caveat:** "Held-out benign: 1/32 blocked (a security-awareness memo quoting an injection phrase; same as before #46), and 4/32 raise an alert without a block. Held-out attacks: 14 of 16 hand-written paraphrases detected, but on an independent reviewer's 6 further paraphrases, 1 detected, so recall on novel phrasings is limited — see PR #46."
- Never say we "beat the baseline" across the board. Say "8KB evasion: 2/2 fixtures", which is the case we do win.
- Latency: say only "under half a millisecond".

## Encores (after 3:00, or in Q&A)

- **3A OpsBot (Path A).** Run `node track3a/run-demo.mjs` (about 2 s). It prints the layering table: Undefended
  LEAKED ×2 … Hardened + proxy + egress all blocked, benign OK. Fallback: `open track3a/RESULTS.md` (the committed table).
- **Live egress.** `scripts/egress-demo.sh both` takes about a minute and runs on its own compose stack.
- **SOC handoff (optional, if available).** This is open PR #86, `soc-handoff`. If it has merged, `scripts/soc-handoff.sh`
  sends the Track 3 alerts to Track 1's SOC Brief, which turns them into a plain-English analyst brief (offline, no
  LLM key). It prints the brief and also writes `.eval/soc-handoff/brief.md`. If it hasn't merged, skip it.

## If X breaks

- **DVAA down** (`up` fails, or Colima crashed): run `demo/run-demo.sh --no-dvaa --no-teardown`. Every beat replays from
  the committed `captures/`, and Beat 4 falls back to the recording on its own. If Colima itself is the problem, try
  `colima restart` once at T-30. Never do it on stage.
- **Proxy port busy:** the live Beat 4 proxy uses an ephemeral port (`SENTINEL_LISTEN_PORT=0`), so it can't collide.
  A manual encore on the shipped config (:8080) needs
  `SENTINEL_LISTEN_PORT=8090 node sentinel/proxy/cli.mjs --config sentinel/config/sentinel.config.json`.
  If the dashboard port is busy, use `EVAL_DASHBOARD_PORT=9101`. Find what holds a port with `lsof -nP -iTCP:9100 -sTCP:LISTEN`.
- **Dashboard blank:** press Cmd-R, then reload with an explicit capture (`?stage=1&capture=proxy-blocked`). If it's
  still blank, stay on the terminal. Every beat prints there.
- **Live 403 fails** (prints `WARN live proxy unavailable; showing the recording`): `run-demo.sh` has already switched
  to the recorded block. Say: **"Same request, same detector: here's the block from our recorded run against live DVAA."**
- **Anything else:** say "Let me show you the recorded run" and play `~/Desktop/fallback-demo.mov` from the matching beat.

## After

- Run `scripts/eval.sh dashboard-stop`, then `scripts/eval.sh down`, then `colima stop`.
- **Make the fallback recording before 18:00:**
  1. Press Cmd-Shift-5 → *Record Selected Portion*, covering the terminal and the dashboard.
  2. Options: Microphone **None**, Save to **Desktop**. Click **Record**.
  3. Run `demo/run-demo.sh --auto --keep-dvaa --no-teardown`.
  4. Stop with the ⏹ in the menu bar (or Cmd-Ctrl-Esc).
  5. Rename the file to `~/Desktop/fallback-demo.mov`. Keep it **out of the repo**, because it isn't gitignored. Put a copy on USB.
