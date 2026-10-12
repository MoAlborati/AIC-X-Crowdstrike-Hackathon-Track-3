# PRESENTER — 18:00 run-of-show (Catherine, Mac, screen share)

One page. Follow it top to bottom. **Hard stop at 3:00, and don't debug on stage: switch to the fallback.**
Spoken lines are the short versions from `demo/SCRIPT.md`. Judge answers are in `demo/QA-PREP.md`.
All commands run from the repo root, which must be under `~` because Colima only shares `$HOME`.

> **Check at T-30:** these PRs may not have merged yet. **#70** (`mac-compat`) makes `eval.sh` and `run-demo.sh` work on
> bash 3.2. If it isn't merged, `git checkout mac-compat`. **#50** (`t9-beat4-fix`) adds live Beat 4 (200/403)
> and Beat 7. If it isn't merged, Beat 4 shows only the recording. **T5-stage** adds `?stage=1`. If it isn't merged, use `?id=`.

## T-30 min checklist

- [ ] `colima start --cpu 4 --memory 6`, then confirm with `docker info | head -3`
- [ ] `export PATH=/opt/homebrew/opt/node@24/bin:$PATH`, then confirm `node --version` prints `v24.x`
- [ ] `git pull` and `scripts/eval.sh doctor`. Expect all PASS. Every FAIL prints its macOS `fix:` line.
- [ ] `scripts/eval.sh up`. Expect `all 22 DVAA ports answer 200` and `bound to 127.0.0.1`.
- [ ] Pre-warm the dashboard on a fixed port with `EVAL_DASHBOARD_PORT=9100 scripts/eval.sh dashboard`, then open these tabs:
  - T5-stage merged: `http://127.0.0.1:9100/?stage=1&capture=vulnerable`, then `&capture=aim-twin`, then `&capture=proxy-blocked`
  - otherwise: `http://127.0.0.1:9100/?id=attack/aim-ab.demo&run=runA`, then `run=runB`
- [ ] Dry run: `demo/run-demo.sh --auto --keep-dvaa --no-teardown`. The Summary must say `demo run clean`.
- [ ] Have the fallback video open in QuickTime, paused at 0:00 (`~/Desktop/fallback-demo.mov`; see **After**).
- [ ] Quit Slack, Mail, Messages and anything else that pops up. Turn on **Do Not Disturb** (Control Center → Focus).
- [ ] Screen share: set the display to 1920×1080 or the "Default" scaling (System Settings → Displays). Share the screen, not one window, so you can switch between the terminal, the browser and the slides.
- [ ] Terminal: Cmd-+ up to a font of at least 20pt, dark theme. Terminal on the left, dashboard on the right.
- [ ] At T-2, run `demo/run-demo.sh --keep-dvaa --no-teardown` (interactive). Let the 3 preflights pass, then **stop
      at the first "press Enter"** before Beat 3. That's the starting position.

## Run of show (3:00 clock; Enter advances each beat)

| time | beat | what to say (one line) | exact command or click | audience sees | fallback if it fails |
|---|---|---|---|---|---|
| 0:00 | 1 Hook | "Air Canada lost a tribunal case over its chatbot… each prompt becomes an entry point for the adversary." | slide 2 | two incidents and the Kurtz quote | keep talking (slides only) |
| 0:20 | 2 Structure | "Your AI agent is a bank teller who obeys notes slipped into deposit envelopes." | slide 3 | confused-deputy diagram | — |
| 0:40 | **3** Exploit (red) | "RAGBot 7005, one poisoned document: the admin secret and an SSN just left the building." | **Enter** · dashboard tab `vulnerable` | `submit_to_index`, `true`, `dvaa-admin-secret … 123-45-6789` | play the video from 0:40 |
| 1:00 | **3b** 8KB evasion | "DVAA's scanner reads only the first and last 8KB; this hides in the middle. We scan everything: 2 of 2 caught." | **Enter** | `inMiddleGap:true`, `evadesDvaaBaseline:true`, `t3Caught:2` | **never cut**; read the line from the slide |
| 1:20 | **4** Live block | "Same agent through SentinelProxy. A normal question passes… now the attack: 403, before it reaches the model." | **Enter** · dashboard tab `proxy-blocked` | live `HTTP 200`, then `HTTP 403`, `sentinel-t3`, then the T4 alert (ATLAS, OWASP LLM01) | automatic: WARN + recording (see below) |
| 1:40 | **4b** Egress | "RepoBot reads its payload in-process, so the egress guard stops the exfil at the tool boundary." | **Enter** | `deny` rows, `RESULT block: PREVENTED`, `(no canary hits)` | read `PREVENTED`, move on |
| 1:50 | **5a** AIM twin | "Its twin, RAGBot-AIM 7014, is denied. We protect the agents you can't rebuild." | **Enter** · tab `aim-twin`, then slide 6 | `false` + denial reason; red / green / green columns | slide 6 only |
| 2:05 | 6 How | "Confirmation of Payee, limited power of attorney, dead-man switch: fail closed, never truncate." | slide 7 | field → mechanism → rule | trim to two mechanisms |
| 2:30 | **7** Close | Read the numbers the terminal prints, verbatim. Then: "A working slice of Falcon AIDR at the tool boundary. Thank you." | **Enter** · slides 8 → 10 | T3 vs DVAA table: recall, FP, `8KB evasion 2/2`, p95 < 0.5 ms (DVAA has the higher recall; our 0 FP is on the 164-case benign corpus) | read the numbers off the slide |
| 3:00+ | **3A OpsBot** (Path A, encore or Q&A) | "We also built our own agent: no single layer stops both attacks, all three together do, and both benign tasks still pass." | `node track3a/run-demo.mjs` (~2 s) | the layering table: Undefended LEAKED ×2 … Hardened + proxy + egress all blocked, benign OK | `open track3a/RESULTS.md` (committed table) |

Running long? Cut the benign pass in Beat 4 first, then trim Beat 6. **Never cut 3b.**

## If X breaks

- **DVAA down** (`up` fails, or Colima crashed): run `demo/run-demo.sh --no-dvaa --no-teardown`. Every beat replays from
  the committed `captures/`, and Beat 4 falls back to the recording by itself. If Colima itself is the problem, try `colima restart` once at T-30, never on stage.
- **Proxy port busy:** the live Beat 4 proxy uses an ephemeral port (`SENTINEL_LISTEN_PORT=0`), so it can't collide. A
  manual encore on the shipped config (:8080) needs `SENTINEL_LISTEN_PORT=8090 node sentinel/proxy/cli.mjs --config sentinel/config/sentinel.config.json`.
  Dashboard port busy: `EVAL_DASHBOARD_PORT=9101`. Find the holder with `lsof -nP -iTCP:9100 -sTCP:LISTEN`.
- **Dashboard blank:** Cmd-R. Then reload with an explicit capture: `?stage=1&capture=proxy-blocked` (T5-stage) or
  `?id=attack/aim-ab.demo&run=runA` (main). Still blank? Stay on the terminal. Every beat prints there.
- **Live 403 fails** (prints `WARN live proxy unavailable; showing the recording`): `run-demo.sh` already switched to the
  recorded block. Say: **"Same request, same detector: here's the block from our recorded run against live DVAA."**
- **Anything else:** say "Let me show you the recorded run" and play `~/Desktop/fallback-demo.mov` from the matching beat.

## After

- `scripts/eval.sh dashboard-stop`, then `scripts/eval.sh down`, then `colima stop`.
- **Make the fallback recording (do this before 18:00):** press Cmd-Shift-5 → *Record Selected Portion* (terminal + dashboard)
  → Options: Microphone **None**, Save to **Desktop** → **Record**. Run `demo/run-demo.sh --auto --keep-dvaa --no-teardown`.
  Stop with the ⏹ in the menu bar (or Cmd-Ctrl-Esc). Rename it `~/Desktop/fallback-demo.mov`. Keep it **out of the repo**: it isn't gitignored. Put a copy on USB.
