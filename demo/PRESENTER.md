# PRESENTER — 18:00 run-of-show (Catherine, Mac, screen share)

One page. Follow it top to bottom. **Hard stop at 3:00, and don't debug on stage: switch to the fallback.**
Every quoted line below is copied word for word from `demo/SCRIPT.md`. The Beat 3–7 lines are also the `say`
lines of `demo/run-demo.sh`, which prints each one in cyan, and `demo/run-demo.sh --check-script` fails if they drift.
If you need to shorten a line, drop sentences from it. Don't reword it.
Judge answers: [`demo/QA-PREP.md`](QA-PREP.md). Read it once before 18:00.
All commands run from the repo root. Under Colima the repo must be somewhere under `~`, because Colima only shares `$HOME`.

## T-30 min checklist

- [ ] `colima start --cpu 4 --memory 6`, then confirm with `docker info | head -3`.
- [ ] `export PATH=/opt/homebrew/opt/node@24/bin:$PATH`, then confirm that `node --version` prints `v24.x`.
- [ ] `git pull`, then `scripts/eval.sh doctor`. Expect all PASS. Every FAIL prints its macOS `fix:` line.
- [ ] `scripts/eval.sh up`. Expect `all 22 DVAA ports answer 200` and `bound to 127.0.0.1`.
- [ ] Dry run: `demo/run-demo.sh --auto --keep-dvaa --no-teardown`. It starts the dashboard on :9100 **with the real
      SentinelProxy alerts** (preflight 3/3), so don't start the dashboard by hand. The Summary must say
      `demo run clean`, and Beat 4 must show a **live** `200` then `403`, with no `WARN live proxy unavailable`.
- [ ] Leave that dashboard running (`--no-teardown`) and open four tabs, in beat order:
  - Beat 3: `http://127.0.0.1:9100/?stage=1&capture=vulnerable`
  - Beat 4: `http://127.0.0.1:9100/?id=live/proxy-7005&run=run&step=last` (should read "High 70 IndirectPromptInjection · Blocked · pre-forward")
  - Beat 4b: `http://127.0.0.1:9100/?id=live/egress-boundary&run=run&step=last` (should show four "Blocked · egress deny" cards)
  - Beat 5a: `http://127.0.0.1:9100/?stage=1&capture=aim-twin`
- [ ] Have the fallback video open in QuickTime, paused at 0:00 (`~/Desktop/fallback-demo.mov`; see **After**).
- [ ] Quit Slack, Mail, Messages and anything else that pops up. Turn on **Do Not Disturb** (Control Center → Focus).
- [ ] Screen share: set the display to 1920×1080 or the "Default" scaling (System Settings → Displays). Share the
      whole screen, not one window, so you can switch between the terminal, the browser and the slides.
- [ ] Terminal: Cmd-+ until the font is at least 20pt, dark theme. Put the terminal on the left and the dashboard on the right.
- [ ] At T-2, run `demo/run-demo.sh --keep-dvaa --no-teardown` (interactive). Let the preflights pass (row 0 is the
      script-drift check), then **stop at the first "press Enter"**, before Beat 3. That's your starting position.

## Run of show (3:00 clock; Enter advances each beat)

Main runs the beats in this order: 1 → 2 → **3 → 3b → 4 → 4b → 5a** → 6 → **7**. Beats 1, 2 and 6 are slides only;
`run-demo.sh` drives the beats in bold.

**0:00 · Beat 1 Hook** · slide 1 → 2 (two incidents + the Kurtz quote) · fallback: keep talking
> "Air Canada lost a tribunal case over its chatbot. A Chevy dealer's chatbot 'agreed' to sell a 2024
> Tahoe for $1. CrowdStrike's CEO put it plainly: 'Each prompt becomes an entry point for the
> adversary.' Today that prompt can arrive inside a document your agent reads."
> "Everything you'll see runs in a deterministic sandbox, no LLM, and most of it is recorded. We'll say which."

**0:20 · Beat 2 Structure** · slide 3 (confused-deputy diagram)
> "Picture a new bank teller who obeys any note slipped into a deposit envelope. The teller has the
> authority, the customer owns it, and the attacker can't touch the vault directly, so the attacker
> writes the note. That's the confused deputy, Hardy 1988. Your AI agent is that teller, and every RAG doc,
> web page and repo file is an envelope."

**0:40 · Beat 3 Exploit (red)** · **Enter**, then the dashboard tab `vulnerable` · fallback: play the video from 0:40
> "Recorded run. This is RAGBot on port 7005, an intentionally vulnerable agent from the organizers' DVAA sandbox."
> "We send it one request carrying poisoned retrieved content, the client-side RAG pattern, taken from DVAA's own attack corpus."

Screen: `submit_to_index`, `true`, `… dvaa-admin-secret | … 123-45-6789` (fake sandbox values).
> "It called submit_to_index, and the admin secret and an SSN just left the building."

Pause for two seconds and let it land.

**1:00 · Beat 3b 8KB evasion (red, recorded, 10 seconds max)** · **Enter** · fallback: read the lines from the slide
> "Recorded fixtures. DVAA's own scanner only looks at the first and last 8KB. This one hides in the middle, so the scanner sees nothing."

Screen: `inMiddleGap:true`, `evadesDvaaBaseline:true`, `fullScanFindsSignal:true`, then `t3Caught: 2`.
> "SentinelProxy scans the full payload and never truncates. 8KB evasion: 2 out of 2 fixtures caught."

**1:10 · Beat 4 Detect → alert → block (green, the one live beat)** · **Enter**, then the dashboard tab `?id=live/proxy-7005&run=run&step=last`.
`run-demo.sh` starts the real shipped proxy (`sentinel/proxy/cli.mjs`, block mode, `sentinel-t3`) on an ephemeral
loopback port in front of 7005 and sends two `curl`s to it.
> "Same agent, same request, but now it goes through SentinelProxy. First, a normal question passes untouched."

Screen: live `200`.
> "Now the attack."

Screen: live `403`, `blocked_request`, `detector: sentinel-t3`, then (say "recorded") the recording and the T4 alert
(`IndirectPromptInjection`, ATLAS AML.T0051.001, OWASP LLM01, ASI01, OASB-1, Blocked).
> "Blocked at the request boundary, before it was ever forwarded to the model. The verdict comes from our T3 detector, sentinel-t3, with reason codes exfil_instruction_inbound, injection_markers, payee_not_confirmed. Prevention is request-side. If a honeytoken shows up in a response instead, the tool already ran (alert-only for prevention), but in block mode the reply is withheld, so the secret never reaches the client."

> "Nothing was forwarded, so nothing could be exfiltrated."

Fallback is automatic. If the terminal prints `WARN live proxy unavailable; showing the recording`, keep going (see **If X breaks**).

**1:40 · Beat 4b Egress default-deny (green, recorded, the blocking story)** · **Enter** · fallback: read `PREVENTED` and move on
> "Recorded egress run, and this is our real blocking story: default-deny egress at the tool boundary. RepoBot reads its payload inside the agent, so the proxy cannot stop that exfil. The egress guard does. It denies non-allowlisted destinations and honeytokens, and fails closed."

Screen: `deny` rows (RAGBot 7005 honeytokens, RepoBot 7022 `bootstrap.sh` fetch + credential post), then
`RESULT block: PREVENTED`, `RESULT repobot block: PREVENTED`, `(no canary hits)`. Dashboard: switch to the tab
`?id=live/egress-boundary&run=run&step=last`, which shows four "Blocked · egress deny" cards, one per deny.
> "The api.oa2a.org deny is DVAA's startup telemetry, blocked by the allowlist."

**1:55 · Beat 5a AIM twin (recorded)** · **Enter**, then the tab `aim-twin`, then slide 6 (red / green / green) · fallback: slide 6 only
> "Recorded run. Its twin, RAGBot-AIM 7014, is the same code with its capability guard switched on, and it is denied."

Screen: `false` + the AIM denial reason.
> "Secure-by-design works when you can rebuild the agent. We protect the agents you can't rebuild."

**2:05 · Beat 6 How it works** · slide 7 (field → mechanism → rule) · cut this first if you're running long
> "We borrowed two controls from fields that already solved the confused deputy. Banks check the payee before money
> moves, so our egress guard denies any destination that isn't on the allowlist. And a dead-man switch fails closed: if our
> scanner times out or the input is too big, egress is denied and we raise an alert."

**2:20 · Beat 7 Outcome + "we attacked ourselves" + close** · **Enter**, then slides 8 → 10 · fallback: read the numbers off the slide

The terminal prints the T3 vs DVAA table: detection recall 67.7% vs 65.6%, prevention 41.8% vs 63.0%, benign FP 0/164 vs 21/164,
`8KB evasion: 2/2`, latency median 0.082 ms / p95 ~0.4 ms.
> "From the committed scoring run, on 189 attacks and 164 benign cases, labelled by DVAA's ground truth and the published benchmarks. We detect slightly more than DVAA's scanner. DVAA prevents more, 63 percent versus our 42, but its scanner also blocks 12.8 percent of benign traffic. Our benign set is one we also tuned on. Where data actually leaves, we prevent 57 of 71 exfil attempts with 0 of 164 legitimate requests blocked; DVAA prevents 64 of 71 but blocks 21 of 164 legitimate requests. 8KB evasion: 2 out of 2 fixtures. In-detector latency: median under a tenth of a millisecond, p95 around half a millisecond."

> "We attacked ourselves too. On 600 held-out public jailbreaks we never tuned on, we prevent zero, because none of them has anywhere to send your data. And spacing out an account number slips past our blocking rule today. Both are on our limitations list."

> "Regex at the front door is not enough. Default-deny egress at the tool boundary is what actually stops the data. SentinelProxy is an exfil-focused guardrail for tool-using agents. Thank you."

Running long? Cut the benign pass in Beat 4 first, then Beat 6, then shrink 3b. **Never cut the "we attacked ourselves" line.**

## Claim wording (for Q&A; also see `demo/QA-PREP.md`)

- **Never headline "100% precision" or "0% FP".** Say "0 of 164 benign blocked, on a benign set we also tuned on". It is a small sample, not a guarantee.
- **Never say "a working slice of Falcon AIDR".** Say "an exfil-focused guardrail for tool-using agents"; we complement AIDR, we haven't integrated with it.
- **Say "recorded"** on Beats 3, 3b, 4b and 5a, and on the recorded half of Beat 4. Only the Beat 4 200/403 is live.
- **The comparison one-liner** (matches Beat 7 after #95): "DVAA's baseline prevents more, 63 percent versus our 42; we detect slightly more, with zero false alarms on the 164 benign cases versus its 21, and we catch the 2 cases that evade its 8KB window."
- Don't say "DVAA has higher recall" without a qualifier. Since #46/#95 that's only true for **prevention**; on detection T3 is ahead (67.7% vs 65.6%).
- **Held-out FP caveat:** "Held-out benign: 1/32 blocked (a security-awareness memo quoting an injection phrase; same as before #46), and 4/32 raise an alert without a block. Held-out attacks: 14 of 16 hand-written paraphrases detected, but on an independent reviewer's 6 further paraphrases, 1 detected, so recall on novel phrasings is limited — see PR #46."
- Never say we "beat the baseline" across the board. "8KB evasion: 2/2 fixtures" is n=2 against a weakness DVAA built in on purpose, so don't sell it as a differentiator.
- Latency: say exactly "median under a tenth of a millisecond, p95 around half a millisecond". p95 moves between about 0.39 and 0.52 ms from run to run, so never say "under half a millisecond".

## Encores (after 3:00, or in Q&A)

- **3A OpsBot (Path A).** Run `node track3a/run-demo.mjs` (about 2 s). It prints the layering table: Undefended
  LEAKED ×2 … Hardened + proxy + egress all blocked, benign OK. Fallback: `open track3a/RESULTS.md` (the committed table).
- **Live egress.** `scripts/egress-demo.sh both` takes about a minute and runs on its own compose stack.
- **SOC handoff (optional).** PR #86 (`soc-handoff`) is merged: `scripts/soc-handoff.sh`
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
- **Dashboard blank:** press Cmd-R, then reload with an explicit capture (`?id=live/proxy-7005&run=run&step=last`). If the alert cards say "No detector verdicts recorded", the dashboard was started without the stage alerts: run `scripts/eval.sh dashboard-stop` and re-run `demo/run-demo.sh --no-teardown`. If it's
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
