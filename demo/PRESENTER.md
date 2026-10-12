# PRESENTER — 18:00 run-of-show (Catherine, Mac, screen share)

One page. Follow it top to bottom. **Hard stop at 3:00, and don't debug on stage: switch to the fallback.**
Every quoted line below is copied word for word from `demo/SCRIPT.md`. The Beat 3–7 lines are also the `say`
lines of `demo/run-demo.sh`, which prints each one in cyan, and `demo/run-demo.sh --check-script` fails if they drift.
If you need to shorten a line, drop sentences from it. Don't reword it.
Judge answers: [`demo/QA-PREP.md`](QA-PREP.md). Read it once before 18:00.
All commands run from the repo root. Under Colima the repo must be somewhere under `~`, because Colima only shares `$HOME`.

## T-30 min checklist

- [ ] `caffeinate -dimsu &` so the Mac never sleeps (a sleep kills Colima's port forwarder). Check that
      `pmset -g | grep sleep` shows `sleep 1` overridden while it runs.
- [ ] `colima start` (plain: don't pass `--cpu`/`--memory`, which would shrink the VM), then confirm with `docker info | head -3`.
- [ ] A Node 24 on PATH: confirm that `node --version` prints `v24.x`. (On Catherine's Mac that's
      `export PATH=$HOME/.cache/node24/bin:$PATH`.)
- [ ] `git pull`, then `scripts/eval.sh doctor`. Expect all PASS. Every FAIL prints its macOS `fix:` line.
- [ ] `scripts/eval.sh up`. Expect `all 22 DVAA ports answer 200` and `bound to 127.0.0.1`.
- [ ] Clean slate before the final dry run: `scripts/eval.sh dashboard-stop; rm -rf .eval/score`, so no stale dashboard
      or rescored latency differs from the slides. **Never run `docker system prune` before 18:00.**
- [ ] Dry run: `demo/run-demo.sh --auto --no-dvaa --no-teardown`. It starts the dashboard **with the real SentinelProxy
      alerts** (preflight 3/3), so don't start the dashboard by hand. The Summary must end
      `demo run clean — no failing beats · dashboard http://127.0.0.1:<port>/`, and Beat 4 must show a **live** `200`
      then `403`, with no `WARN live proxy unavailable`. If :9100 was busy, the runner moves the dashboard to the next
      free port and says so: **use the port it prints**. If no dashboard starts, the run FAILS; it never says "clean" then.
- [ ] Leave that dashboard running (`--no-teardown`) and open three tabs in beat order, all in **stage mode at the last
      step** (replace 9100 if the runner printed another port):
  - Beat 3: `http://127.0.0.1:9100/?stage=1&capture=vulnerable&step=last`
  - Beat 4: `http://127.0.0.1:9100/?stage=1&capture=proxy-blocked&step=last` (blocked card; no stat tiles)
  - Beat 4b: `http://127.0.0.1:9100/?stage=1&capture=egress-blocked&step=last`
  - Beat 5a: **no tab.** Slide 6 only.
- [ ] **T-5: warm the live Beat 4b run.** `scripts/encore-two-layer.sh block` once (cold start about 22 s; it must
      end `ENCORE PASS`). This caches images and layers so the run inside Beat 4/4b finishes in about 20 s. Never run
      the `observe` control on stage: it is recorded only.
- [ ] Have the fallback video open in QuickTime, paused at 0:00: `~/Desktop/fallback-demo.mov` (the one name used
      everywhere; see **After** and `demo/slides/VIDEO-CHECKLIST.md`).
- [ ] Quit Slack, Mail, Messages and anything else that pops up. Turn on **Do Not Disturb** (Control Center → Focus).
- [ ] Screen share: set the display to 1920×1080 or the "Default" scaling (System Settings → Displays). Share the
      whole screen, not one window, so you can switch between the terminal, the browser and the slides.
- [ ] Terminal: **18pt**, full screen height, dark theme. Terminal on the left, dashboard on the right.
      **Cmd-K before every Enter**, so each beat starts at the top of the window and nothing scrolls off.
- [ ] At T-2, run `demo/run-demo.sh --no-dvaa --no-teardown` (interactive; `--no-dvaa` so a dead Colima forwarder
      can't hang preflight 2 for minutes; Beat 4 still goes live whenever 7005 answers). Interactive mode pauses after
      **each** of Preflight 1/3, 2/3 and 3/3. **Park at the prompt after "Preflight 3/3"**, then Cmd-K. That's your
      starting position: the next Enter starts Beat 3.

## Run of show (3:00 clock; Cmd-K, then Enter, for each beat)

Order: 1 → 2 → **3 → 3b → 4 → 4b → 5a** → 6 → **7**. Beats 1, 2 and 6 are slides only; `run-demo.sh` drives the
beats in bold. 372 spoken words, about 2:47 with transitions. Every quoted line is word for word from `demo/SCRIPT.md`.
Don't read ticket numbers, reason codes or framework IDs aloud; they're on the slides for Q&A.

**0:00 · Beat 1 Hook** · slide 1 → 2 (incidents and the Kurtz quote stay on the slide, unspoken)
> "In under a minute I'll make an AI agent send its admin password to an attacker using one poisoned document, then stop it without touching its code."
> "It's a deterministic sandbox, no LLM."

**0:15 · Beat 2 Structure** · slide 3
> "Your agent is a bank teller who obeys any note slipped into a deposit envelope. Every document, web page and repo file it reads is an envelope. The attacker never breaks in; the teller does the work."
> "We protect the agents you can't rebuild, from the outside."

**0:35 · Beat 3 Exploit (red)** · Cmd-K, **Enter**, then the `vulnerable` tab · fallback: play the video from 0:35
> "Recorded. A deliberately vulnerable agent from the organizers' sandbox gets one document with a hidden instruction."

Screen: `submit_to_index`, `true`, `… dvaa-admin-secret | … 123-45-6789` (fake sandbox values).
> "It just sent the admin password and an SSN to the attacker's server."

Pause for two seconds and let it land.

**0:50 · Beat 3b 8KB evasion (red, recorded)** · Cmd-K, **Enter**
> "Recorded. The sandbox's scanner reads only the first and last 8 KB, so attackers hide the payload in the middle. We read every byte, typically in under a tenth of a millisecond."

Say "2 of 2 fixtures" only if a judge asks.

**1:04 · Beat 4 Block (green, live)** · Cmd-K, **Enter**
> "Same agent, same document, now through SentinelProxy. First, a normal question: it passes."

Screen: live `200`.
> "Now the attack."

Screen: live `403`.
> "Refused before the agent ever saw it: the document slipped in an order to send data somewhere the user never named."

The runner **pauses here** so the 200/403 stays on screen. Switch to the `proxy-blocked` tab while you speak, then
Cmd-K and Enter: the recorded evidence prints (unspoken). Fallback is automatic: if the terminal prints
`WARN live proxy unavailable; showing the recording`, say "recorded" and keep going (see **If X breaks**).

**1:24 · Beat 4b Egress guard (green, LIVE)** · Cmd-K, **Enter**, then the `egress-blocked` tab. The live two-layer
run (`scripts/encore-two-layer.sh block`) started in the background at Beat 4 and has finished by now.
> "Live now, in its own sandbox: an agent that reads the poison itself."

Screen (live): `LAYER1_PROXY_HTTP 403`, `PROXY … prevents=false`, three `deny` lines, **`GROUND_TRUTH canary hits …: 0`**, `ENCORE PASS`.
> "Our proxy only flags that after the tool has run. So the egress guard denied every unlisted destination, and in this run no secret reached the attacker."

If the terminal prints `WARN live egress run unavailable`, replace the first line with **"That live run didn't come up;
this is the same run, recorded."** and point at `RESULT … PREVENTED` / `(no canary hits)`. The runner pauses after the
result; Cmd-K, Enter for the recorded evidence (unspoken).

**1:41 · Beat 5a AIM twin** · Cmd-K, **Enter**, then **slide 6 only** (red / green / green). No dashboard tab.
> "Recorded. The other fix is rebuilding the agent with a capability guard: its twin is denied. That works if you own the code. Most companies don't."

**1:53 · Beat 6 Guest list** · slide 7 · cut this first if you're running long
> "Only you decide where data goes. Our egress guard is a guest list, not a lie detector: any destination not on the list is denied, whatever the words say."

**2:06 · Beat 7 Outcome + close** · Cmd-K, **Enter**, then slides 8 → 10 (the full table is on slide 8; don't read it)
> "On 189 attacks and 164 normal requests, we detect slightly more than the sandbox's scanner. It stops more outright, 63 percent to our 42, but it blocks one in eight normal requests. We blocked zero."

> "We attacked ourselves too: on 600 public jailbreaks we never tuned on, we prevent zero, because none has anywhere to send data. Our known misses are listed in the repo."

> "Flagging isn't stopping: in our watch-only run, the attacker still got the key. So we built the layer that doesn't need to read. A document can ask. Only the user can authorize. Thank you."

Teardown and the Summary print straight after Beat 7; switch to slide 10 before they scroll in.
Running long? Cut Beat 6 first, then the second sentence of Beat 3b. **Never cut the "we attacked ourselves" line.**

**If a judge bypasses the proxy live** (spacing, homoglyphs, a polite rephrase): "Thank you. That's layer 1. Layer 2
doesn't read words." Then point at the egress guard: it decides on the destination host, not the wording.
**Never say "nothing gets out":** a split honeytoken sent to an allowlisted host still passes.

## Claim wording (for Q&A; also see `demo/QA-PREP.md`)

- **Never headline "100% precision" or "0% FP".** Say "0 of 164 benign blocked, on a benign set we also tuned on". It is a small sample, not a guarantee.
- **Never say "a working slice of Falcon AIDR".** Say "an exfil-focused guardrail for tool-using agents"; we complement AIDR, we haven't integrated with it.
- **Say "recorded"** on Beats 3, 3b, 4b and 5a, and on the recorded half of Beat 4. Only the Beat 4 200/403 is live.
- **The comparison one-liner** (matches Beat 7 after #95): "DVAA's baseline prevents more, 63 percent versus our 42; we detect slightly more, with zero false alarms on the 164 benign cases versus its 21, and we catch the 2 cases that evade its 8KB window."
- Don't say "DVAA has higher recall" without a qualifier. Since #46/#95 that's only true for **prevention**; on detection T3 is ahead (67.7% vs 65.6%).
- **Held-out FP caveat:** "Held-out benign: 1/32 blocked (a security-awareness memo quoting an injection phrase; same as before #46), and 4/32 raise an alert without a block. Held-out attacks: 14 of 16 hand-written paraphrases detected, but on an independent reviewer's 6 further paraphrases, 1 detected, so recall on novel phrasings is limited — see PR #46."
- Never say we "beat the baseline" across the board. "8KB evasion: 2/2 fixtures" is n=2 against a weakness DVAA built in on purpose, so don't sell it as a differentiator.
- Latency on stage: "typically in under a tenth of a millisecond" (the median, checked by `run-demo.sh`). If asked for more: "median under a tenth of a millisecond, p95 around half a millisecond". p95 moves between about 0.39 and 0.52 ms from run to run, so never say "under half a millisecond".
- **"The attacker still got the key"** (closing line) is the recorded **watch-only (observe-mode) egress run**: the guard flagged the FAKE AWS key and forwarded it (`sentinel/egress/evidence-observe.jsonl`). "No secret reached the attacker" (Beat 4b) is the recorded **block** run only. Never generalize either to "nothing gets out".

## Encores (after 3:00, or in Q&A)

- **3A OpsBot (Path A).** Run `node track3a/run-demo.mjs` (about 2 s). It prints the layering table: Undefended
  LEAKED ×2 … Hardened + proxy + egress all blocked, benign OK. Fallback: `open track3a/RESULTS.md` (the committed table).
- **Live egress.** `scripts/egress-demo.sh both` takes about a minute and runs on its own compose stack.
- **SOC handoff (optional).** PR #86 (`soc-handoff`) is merged: `scripts/soc-handoff.sh`
  sends the Track 3 alerts to Track 1's SOC Brief, which turns them into a plain-English analyst brief (offline, no
  LLM key). It prints the brief and also writes `.eval/soc-handoff/brief.md`. If it hasn't merged, skip it.

### Encore (only if asked): both layers, one attack

**This now runs live inside the talk as Beat 4b** (`run-demo.sh` starts it at Beat 4). Re-run it by hand only if a judge
asks to see it again, or asks "what about attacks the chat proxy can't see?": `scripts/encore-two-layer.sh block`. It takes about 25 s on its own compose project (`sentinel-encore`, net
`10.231.53.0/24`, override with `ENCORE_PROJECT` / `ENCORE_NET`) and only removes its own containers.
- What happens: a benign "review my repo" turn passes the chat proxy. RepoBot reads DVAA's poisoned `AGENTS.md`
  and tries to POST fake credentials out. The egress inspector denies it (`destination_not_allowlisted`,
  `honeytoken_match`), and the last line reads **`GROUND_TRUTH canary hits: 0`**, followed by `ENCORE PASS`.
- Say: **"The chat layer only sees the response, so it alerts. The egress layer decides on the host, and the attacker's server got nothing."**
- Control, if anyone doubts it's live: `scripts/encore-two-layer.sh observe` **after the talk only** (it lets the fake key land). The same attack lands with 2 canary hits and is recorded. On stage, cite the recorded control instead.
- If a judge bypasses the request-side proxy live: "Thank you. That's layer 1. Layer 2 doesn't read words." Receipt: critic B2's run in #112 put 20 different role-play jailbreak framings through the full stack: 0 of 40 canary hits with egress in block mode, 40 of 40 relaxed, and identical egress verdicts for all 20 (not committed as a capture, so it's a Q&A answer, not a spoken claim).
- Exit 3 means Docker or the DVAA image is missing. Skip the encore.

## If X breaks

- **DVAA down** (`up` fails, or Colima crashed): run `demo/run-demo.sh --no-dvaa --no-teardown`. Every beat replays from
  the committed `captures/`, and Beat 4 falls back to the recording on its own. If Colima itself is the problem, try
  `colima restart` once at T-30. Never do it on stage.
- **Proxy port busy:** the live Beat 4 proxy uses an ephemeral port (`SENTINEL_LISTEN_PORT=0`), so it can't collide.
  A manual encore on the shipped config (:8080) needs
  `SENTINEL_LISTEN_PORT=8090 node sentinel/proxy/cli.mjs --config sentinel/config/sentinel.config.json`.
  If the dashboard port is busy, `run-demo.sh` moves to the next free port and prints it; to pick one yourself, use `EVAL_DASHBOARD_PORT=9101`. Find what holds a port with `lsof -nP -iTCP:9100 -sTCP:LISTEN`.
- **Dashboard blank:** press Cmd-R, then reload with an explicit capture (`?stage=1&capture=proxy-blocked&step=last`). If the alert cards say "No detector verdicts recorded", the dashboard was started without the stage alerts: run `scripts/eval.sh dashboard-stop` and re-run `demo/run-demo.sh --no-teardown`. If it's
  still blank, stay on the terminal. Every beat prints there.
- **Live 403 fails** (prints `WARN live proxy unavailable; showing the recording`): `run-demo.sh` has already switched
  to the recorded block. Say: **"Same request, same detector: here's the block from our recorded run against live DVAA."**
- **Anything else:** say "Let me show you the recorded run" and play `~/Desktop/fallback-demo.mov` from the matching beat.

## After

- Run `scripts/eval.sh dashboard-stop`, then `scripts/eval.sh down`, then `colima stop`.
- **Make the fallback recording before 18:00** with `demo/slides/VIDEO-CHECKLIST.md` (the one procedure): record
  `~/Desktop/fallback-demo-raw.mov`, trim it to **`~/Desktop/fallback-demo.mov`** (the file PRESENTER opens), keep both
  **out of the repo** (`*.mov` isn't gitignored) and put a copy on USB.
