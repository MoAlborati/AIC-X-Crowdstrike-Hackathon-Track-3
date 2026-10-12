# SentinelProxy — demo script (Track 3 core 376 words ≈2:49; expanded run ≈6:00 for the 5–7 min slot)

> Beats follow `planning/STRATEGY.md` §7. Every factual claim spoken on stage uses the "Safe slide wording" from
> `planning/CITATIONS.md`. Don't paraphrase those claims and don't add new ones. **Never fill a metric by hand.**
> Every number comes from the committed T7 scoring output (`sentinel/scoring/results.json`).
>
> **`demo/run-demo.sh` drives every beat below** (interactive, or `--auto` for rehearsal). Each component sits
> behind a single "WIRING REGISTRY" that prints `NOT YET MERGED: <component>` rather than skipping silently if
> one is ever absent.
>
> **Pitch frame (critic D teardown, #112; creative pass 3, #105).** Open on the promise ("in under a minute I'll make an AI
> agent send its admin password to an attacker"; critic D's "20 seconds" is not true on our clock, the leak lands at
> about 0:45). Arc: win (live block), honest loss (the proxy only flags an in-agent
> read after the tool ran), fix (egress default-deny: "a guest list, not a lie detector"), then close on "Flagging isn't
> stopping … So we built the layer that doesn't need to read. A document can ask. Only the user can authorize."
> Egress decides on the destination host, not content, so it holds when the request-side regex is bypassed (spacing,
> homoglyphs; critic B, #112). Never claim request-side robustness, and never say "nothing gets out": a split
> honeytoken sent to an *allowlisted* host still passes.
> We are an exfil-focused guardrail, not a jailbreak classifier and not "a slice of Falcon AIDR". No ticket numbers,
> reason codes or framework IDs are spoken. Beat 7 owns the prevention loss in one clause (63 vs 42) and lands the
> trade-off in plain words: "it blocks one in eight normal requests. We blocked zero." Say "deterministic sandbox, no
> LLM" in the first 15 seconds, say "recorded" on every replay beat, and never headline "100% precision" or "0% FP".
>
> Companion deck: `demo/DECK.md`. Rehearsal + fallback-video checklist + replay log: `demo/REHEARSAL.md`.

## Expanded run (≈6:00 — the 5–7 min 18:00 slot)

@c-awad on #55: **"the 18:00 slot is 5–7 minutes total, slides plus live demo."** So the tight 3-minute Track 3 core
below (Beats 1–7, **unchanged**, with the live Beat 4b) is **wrapped**, not rewritten, by three expansion beats
(full text in "Expansion beats (8–10)" lower down):

| Segment | Beat(s) | Spoken | Speech | ~Wall-clock | Driver |
|---|---|---|---|---|---|
| **Track 3 core** (hook → block → egress → "we attacked ourselves") | 1–7 | 376 words | 2:30 | ≈2:55 | `demo/run-demo.sh` (live Beat 4 + 4b) |
| **OpsBot / Path A** — it generalizes to our own agent | 8 | 76 words | 0:30 | ≈0:35 | `node track3a/run-demo.mjs` |
| **Ciocca** — who pays, how it stands apart, path to launch | 9 | 188 words | 1:15 | ≈1:25 | Slide 12 only |
| **SOC handoff** (only if time) | 10 | 51 words | 0:20 | ≈0:25 | `scripts/soc-handoff.sh` |
| **Total (with SOC)** | | **691 words** | **4:35** | **≈5:45** (≈5:20 without Beat 10) | |

Speech is at 150 wpm; wall-clock adds Enter presses, tab/slide switches, the ~2 s Beat 8 command, and natural
slide-reading pauses on the dense Ciocca and results slides. It lands comfortably inside the 5–7 min slot, with
headroom toward 6:00 from those pauses; trim or add nothing to the core to adjust — cut or restore Beat 10 and Beat 8.

Rules for the expansion: every number comes from `track3a/RESULTS.md`, `demo/slides/VENTURE.md` or
`sentinel/scoring/results.json`; **no market figure is invented** (`VENTURE.md` "Do not say"); the honesty fixes from
#154 stand (DVAA's numbers are always paired, and we never say "nothing gets out"). The expansion beats are
**presenter-driven** (one slide or one terminal command each), so `demo/run-demo.sh --check-script` only polices the
core's spoken lines (Beats 3–7); it does not police Beats 8–10.
**Close handling:** in the expanded run, **drop the final "Thank you." from Beat 7** (dropping a sentence is allowed;
don't reword the rest) and deliver "Thank you." once at the very end, after Beat 9 (or Beat 10 if you run it).
**Running long?** Cut Beat 10 first, then Beat 8; **never cut Beat 9** (the Ciocca criteria) and never cut Beat 7's
"we attacked ourselves" line.

## Ground rules (STRATEGY §8)

- **No live LLM or external API calls in the 3 minutes.** Everything replays deterministically from `captures/`,
  with one exception: Beat 4 sends two local `curl`s through the real shipped proxy (loopback, ephemeral port)
  to the offline DVAA sandbox, whose replies are canned, so the result is deterministic. If the proxy or 7005
  is unreachable, `run-demo.sh` says so and shows the recording instead.
  Beat 4b also runs live: `scripts/encore-two-layer.sh block` on its own compose stack (offline DVAA, canned replies,
  started in the background at Beat 4). If it can't run, `run-demo.sh` says so and shows the recording instead.
- **Don't run the attacker live.** The exploit is DVAA's own bundled payload (APWN-DE-003), already
  captured in `captures/attack/aim-ab.demo.json`.
- **Fallback:** if any command fails, switch straight to the recorded video. Don't debug on stage.
- **Headline pair:** **RAGBot 7005** (vulnerable) ↔ **RAGBot-AIM 7014** (AIM-defended twin, same code).

## Pre-flight (before walking on stage, not timed)

```bash
# The one-command path (does all of 1–4 below, in order, with graceful fallbacks):
demo/run-demo.sh            # interactive, pauses between beats
demo/run-demo.sh --auto     # back-to-back, for rehearsal / recording

# …or the individual steps run-demo.sh drives:

# 1. Target up, all ports bound to 127.0.0.1 (real, merged in T1; eval.sh detects an already-up fleet)
scripts/eval.sh doctor      # preflight: Node/Docker/DVAA checkout + fleet health (PR #20, merged)
scripts/eval.sh up          # bring up the DVAA fleet (or scripts/setup-dvaa.sh up)

# 2. Proxy in front of RAGBot 7005, block mode (proxy #14/#21 + T3 #24, wired by #41)
#    run-demo.sh Beat 4 starts it itself: SENTINEL_MODE=block SENTINEL_LISTEN_PORT=0 \
#      node sentinel/proxy/cli.mjs --config sentinel/config/sentinel.config.json
#    and falls back to the recording (captures/contrast/runs/proxy-block.*) if it can't.

# 3. Real SentinelProxy alerts on the dashboard. The committed captures carry no alert sidecars, so a bare
#    dashboard reads "No detector verdicts recorded". run-demo.sh converts the RECORDED block-mode run with the
#    T10 pipeline (deterministic, into .eval/stage/), then serves captures/ + the two pipeline incidents:
node sentinel/pipeline/cli.mjs convert captures/contrast/runs/proxy-block.proxy.jsonl \
  --egress sentinel/egress/evidence-block.jsonl --out .eval/stage/pipe
SENTINEL_CAPTURES_DIR=.eval/stage/captures SENTINEL_ALERTS_DIR=.eval/stage/pipe/alerts \
  scripts/eval.sh dashboard # sentinel/dashboard/server.mjs on 127.0.0.1:9100 (loopback only)
#    (.eval/stage/captures = a copy of captures/ plus .eval/stage/pipe/captures/live/; run-demo.sh builds it
#    and checks the running dashboard really serves the block alerts, else preflight FAILS.)
#    If :9100 is busy, run-demo.sh moves the dashboard to the next free port and prints the new URL (and the Summary
#    names it); if no dashboard starts at all, the run FAILS instead of reporting "demo run clean".
#    Stage-mode deep links it prints (no stat tiles; each opens at its last step):
#      Beat 3  http://127.0.0.1:9100/?stage=1&capture=vulnerable&step=last
#      Beat 4  http://127.0.0.1:9100/?stage=1&capture=proxy-blocked&step=last    High IndirectPromptInjection · Blocked
#      Beat 4b http://127.0.0.1:9100/?stage=1&capture=egress-blocked&step=last   egress denies, attacker received nothing
#      Beat 5a no tab: Slide 6 only

# 4. Metrics: the stage reads the COMMITTED sentinel/scoring/results.json (Beat 3b + Beat 7).
#    Regenerate only when the corpus or detector changes:
scripts/eval.sh score       # runs sentinel/scoring/cli.mjs
```

All commands run from the repo root.

Screen layout: **left** = terminal (attacker view), **right** = dashboard (detector view). Font ≥ 20pt.

---

## Beat sheet

Spoken lines are in quotes. **376 words in total, 2:30 at 150 words per minute**, plus about 1.5 s per
beat for Enter presses and tab switches (critic D, #112: the old script was 574 words, about 4:10). The time column
is cumulative. No ticket numbers, reason codes or framework IDs are read aloud; they stay on the slides and in Q&A.

### Beat 1 — Hook (0:00–0:15) · Slide 1 → 2

> "In under a minute I'll make an AI agent send its admin password to an attacker using one poisoned document, then stop it without touching its code."
> "It's a deterministic sandbox, no LLM."

*Screen:* slide 2. The two incidents and the Kurtz quote stay **on the slide only**, unspoken.

### Beat 2 — The structure (0:15–0:35) · Slide 3

> "Your agent is a bank teller who obeys any note slipped into a deposit envelope. Every document, web page and repo file it reads is an envelope. The attacker never breaks in; the teller does the work."
> "We protect the agents you can't rebuild, from the outside."

*Screen:* slide 3, the three-actor diagram. "Confused deputy" and Hardy 1988 stay in the slide footer, unspoken.

### Beat 3 — EXPLOIT, red (0:35–0:50) · terminal, then dashboard tab `vulnerable`

> "Recorded. A deliberately vulnerable agent from the organizers' sandbox gets one document with a hidden instruction."

```bash
# Real today: the captured vulnerable run (T1)
jq -r '.runA.toolCalls[0].function.name, .runA.dvaa.exfilExecuted' captures/attack/aim-ab.demo.json
jq -r '.canary.hits[0].query.data' captures/attack/aim-ab.demo.json
```

Expected on screen: `submit_to_index`, `true`, then
`… Admin credentials: dvaa-admin-secret | User John Doe SSN: 123-45-6789` (all fake sandbox values). Zoom the terminal
so that line is the biggest text on screen.

> "It just sent the admin password and an SSN to the attacker's server."

*(Pause for two seconds and let it land.)* *Dashboard:* `?stage=1&capture=vulnerable&step=last` (opens on the finished
graph, not step 1/10).

### Beat 3b — 8KB evasion, red (0:50–1:04) · terminal

> "Recorded. The sandbox's scanner reads only the first and last 8 KB, so attackers hide the payload in the middle. We read every byte, typically in under a tenth of a millisecond."

```bash
# The two mid-document T6 variants: the injection sits between the head/tail 8KB windows, so DVAA's
# head/tail detectAttacks() misses it, while a full scan still carries the signal (PR #10/#15).
jq -rc '{id, docLength:.baseline8kb.docLength, scanEdgeBytes:.baseline8kb.DETECTION_EDGE,
         injectionAtByte:.baseline8kb.injectionOffsetStart, inMiddleGap:.baseline8kb.inMiddleGap,
         evadesDvaaBaseline:.baseline8kb.evadesBaseline, fullScanFindsSignal:.baseline8kb.signalPresentOnFullScan}' \
  captures/variants/fixtures/evasion/eva-pos-middle-001.json captures/variants/fixtures/evasion/eva-bench-middle-001.json
# 8KB evasion: 2/2 fixtures, read from the committed T7 results:
jq -rc '.beatsBaseline | {evasionFixtures:(.eligible|length), t3Caught:.byDetector.t3.beaten, t3Prevented:.byDetector.t3.beatenPrevention, cases:.byDetector.t3.cases}' sentinel/scoring/results.json
```

Frame it as a **class** of evasion, not a score. Say "2 of 2" **only if asked**: it is n=2 fixtures we built, against
a weakness DVAA has on purpose. `run-demo.sh` fails this beat if the fixtures stop showing the 8 KB edge with the payload
in the middle, or if the median latency in `results.json` reaches 0.1 ms.

### Beat 4 — BLOCK, green (1:04–1:24, live) · terminal + dashboard tab `proxy-blocked`

*Every quoted line in Beats 3, 3b, 4, 4b, 5a and 7 is a `say` line of `demo/run-demo.sh`, word for word; the runner
shows each one in cyan. `demo/run-demo.sh --check-script` (also preflight row 0 of every run) fails if they drift.*

> "Same agent, same document, now through SentinelProxy. First, a normal question: it passes."

`run-demo.sh` starts the **real shipped proxy** (`node sentinel/proxy/cli.mjs`, block mode, inspectors
`[substring, sentinel-t3]`) on an ephemeral loopback port in front of 7005, then:

```bash
# benign question -> forwarded untouched
curl -s -o /dev/null -w '%{http_code}\n' -H 'content-type: application/json' \
  --data '{"messages":[{"role":"user","content":"What does the document indexing service do? One sentence, please."}]}' \
  http://127.0.0.1:$PORT/v1/chat/completions                    # -> 200
```

> "Now the attack."

```bash
# DVAA's own aim-ab request body, verbatim from the recording -> refused before forwarding
jq -rs '[.[] | select(.type=="exchange" and .action=="blocked_request")][0].request.body.data' \
  captures/contrast/runs/proxy-block.proxy.jsonl \
  | curl -s -o /dev/null -w '%{http_code}\n' -H 'content-type: application/json' --data-binary @- \
      http://127.0.0.1:$PORT/v1/chat/completions                # -> 403
```

> "Refused before the agent ever saw it: the document slipped in an order to send data somewhere the user never named."

In interactive mode the runner **pauses here** so the live 200/403 stays on screen while you narrate (#124). Cmd-K,
then Enter for the recorded evidence. Nothing below is spoken.

Expected, from the live proxy's own log: `{"action":"blocked_request","status":403,"verdicts":[{"detector":"sentinel-t3",
"reasons":["exfil_instruction_inbound","injection_markers","payee_not_confirmed"]}]}`. `run-demo.sh` **fails** Beat 4 if
the live log or the recording names a different detector or reason set, so "an order to send data somewhere the user
never named" (`exfil_instruction_inbound` + `payee_not_confirmed`) stays true. `payee_not_confirmed` never blocks alone. The
substring inspector has no needles in the shipped config and never fires. **The credit is T3 alone.**

Then (unspoken) the recording of the same block on the live DVAA run, the T4 alert the T10 pipeline built from it, and
the response-side withhold check:

```bash
jq -rc 'select(.type=="exchange" and ((.action//"")|test("block"))) | {action, target, status:.response.status, verdicts:[.verdicts[]|select(.flagged==true)|{phase, detector, disposition, reasons}]}' captures/contrast/runs/proxy-block.proxy.jsonl
jq -rc '.runs[][] | {DetectName, RuleId, SeverityName, Atlas:.TechniqueId, OwaspLlm:[.OwaspLlm[].Id], Agentic:[.OwaspAgentic[].Id], Oasb:.Oasb.Benchmark, Disposition:.PatternDispositionDescription}' captures/contrast/runs/proxy-block.t4-alerts.json
```

*Dashboard (right):* `?stage=1&capture=proxy-blocked&step=last`. Stage mode has no stat tiles, so the screen shows
the blocked card, not "Prevented 41.8% / DVAA 63.0%". Q&A only (QA-PREP #3): a honeytoken in a *response* means the
tool already ran, so prevention there is alert-only, but block mode withholds the reply (T3-fix #56).

### Beat 4b — Egress guard, LIVE, green (1:24–1:41) · terminal, then dashboard tab `egress-blocked`

The climax is live (critic A pass 2, #138; Catherine, #131). `run-demo.sh` starts the real two-layer run,
`scripts/encore-two-layer.sh block` (PR #139), **in the background when Beat 4 starts**. It takes about 20 s even when
warm, because it recreates its own compose stack. By Beat 4b it has finished, and the runner shows its result:
user turn → SentinelProxy (block) → RepoBot 7022 → poisoned `AGENTS.md` → tool egress → egress inspector (block) → canary.
**Warm it at T-5** (`scripts/encore-two-layer.sh block`, once) so images and layers are cached; cold start is about 22 s.

> "Live now, in its own sandbox: an agent that reads the poison itself."

Screen (live): `LAYER1_PROXY_HTTP 403` with the proxy verdicts `phase=response … prevents=false` (it only flagged the
reply after the tool ran), then `LAYER2_EGRESS:` with three `deny` lines, then
`GROUND_TRUTH canary hits …: 0` and `ENCORE PASS`.

> "Our proxy only flags that after the tool has run. So the egress guard denied every unlisted destination, and in this run no secret reached the attacker."

`run-demo.sh` checks each clause against the live output and **FAILS** the beat if it is false: no proxy verdict with
`prevents=true`, no `forward`/`allow` line in layer 2, and 0 canary hits. Then it pauses (interactive) before
printing the recorded evidence below, which is not spoken.

**Fallback (automatic):** if Docker or the DVAA image is missing, or the run doesn't finish in 45 s
(`EGRESS_LIVE_TIMEOUT`), the runner prints `WARN live egress run unavailable` and shows the recorded run instead. Say
this line in place of the "Live now" claim, then the second line as normal:

> "That live run didn't come up; this is the same run, recorded."

```bash
# Recorded block-mode run of scripts/egress-demo.sh (sentinel/egress/, PR #45), always printed after the live result:
jq -rc 'select(.action=="deny") | {host, reasons, canaries:.canary_ids}' sentinel/egress/evidence-block.jsonl
# Ground truth = what the attacker server received (not DVAA's exfilExecuted, which says true even when 403'd):
grep -E '^RESULT|^\(no canary hits\)' demo/captures/egress-demo-block.txt
```

"No secret reached the attacker" is about **this run** only; never generalize it to "nothing gets out" (a split
honeytoken sent to an allowlisted host still passes). The observe-mode control (the proxy says 403, the attacker still
gets the key) is **recorded only**: never run `encore-two-layer.sh observe` on stage.

*Dashboard (right):* `?stage=1&capture=egress-blocked&step=last`.

### Beat 5a — Secure-by-design twin (1:41–1:53) · Slide 6 only

> "Recorded. The other fix is rebuilding the agent with a capability guard: its twin is denied. That works if you own the code. Most companies don't."

*Screen:* **Slide 6 only** (red / green / green). **No dashboard tab:** the aim-twin view still draws the call in red
with "Detected · alert-only", which reads as a leak. The runner still prints the twin's verdict as evidence:

```bash
jq -r '(.runB.dvaa.exfilExecuted // false), .runB.dvaa.aim.denialReason' captures/attack/aim-ab.demo.json
scripts/eval.sh contrast   # verifies the T8 A/B against DVAA's ground truth (recorded runs are checked, never rewritten)
```

| Column | Agent | Verdict | Source |
|---|---|---|---|
| RED | RAGBot 7005 | exfil executed (`dvaa.exfilExecuted=true`) | `aim-ab.demo.json` runA |
| GREEN | RAGBot-AIM 7014 | denied by AIM (`exfilExecuted=false`) | `aim-ab.demo.json` runB |
| GREEN | RAGBot 7005 + SentinelProxy | blocked pre-forward by T3 (`action=blocked_request`, `detector:sentinel-t3`) | `captures/contrast/runs/proxy-block.proxy.jsonl` |

**Prevention map (Q&A):** RAGBot 7005 is blocked request-side, before forwarding. LegacyBot 7003's reply is withheld.
RepoBot 7022 reads its payload inside the agent, so the egress guard is the control that stops it.

### Beat 6 — How it works (1:53–2:06) · Slide 7

> "Only you decide where data goes. Our egress guard is a guest list, not a lie detector: every unlisted destination we tried was denied, whatever the words said."

The data check for this line runs in Beat 4b (`egress_truth_cmd`): the recorded block run has a deny decided on the
destination alone (`destination_not_allowlisted`, no canary in it), so the guard is not reading the words.

*Honest framing if asked:* request-side, `payee_not_confirmed` raises risk but never blocks alone (it blocks only with
`injection_markers` or a staged secret, PR #46); the only unconditional destination block is the egress allowlist. One pre-forward rule (`inbound.exfil_instruction`) carries all the scored preventions; the
honeytoken, provenance and taint layers are tripwires and alerts. The honeytokens are DVAA's own known secrets, so call
them a "known-secret tripwire".

### Beat 7 — Outcome, "we attacked ourselves", close (2:06–2:49) · Slides 8 → 10

`run-demo.sh` prints the T3 vs DVAA table from the committed `sentinel/scoring/results.json`; the full table is on
Slide 8 and is **not read aloud**:

```
                         T3 (SentinelProxy)          DVAA baseline
  detection (any finding)  recall 67.7%  FP 0.0%        recall 65.6%  FP 12.8%
  prevention (pre-forward) recall 41.8%  FP 0.0%        recall 63.0%  FP 12.8%
  8KB evasion: 2/2 fixtures (T3)
  in-detector latency: median 0.082 ms, p95 0.42 ms over 353 cases
```

> "On 189 attacks and 164 normal requests, we detect slightly more than the sandbox's scanner. It stops more outright, 63 percent to our 42, but it blocks one in eight normal requests. We blocked zero."

> "We attacked ourselves too: on a held-out set of injections that do name a destination, our front-door rule stops only 3 percent; the sandbox's scanner stops 51. Our known misses are listed in the repo."

> "Flagging isn't stopping: in our watch-only run, the attacker still got the key. So we built the layer that doesn't need to read. A document can ask. Only the user can authorize. Thank you."

**Every number and comparison** in these lines is asserted by `run-demo.sh` Beat 7, one claim at a time, and the beat
FAILS naming the claim if the data no longer supports it: 189/164, "slightly more" (lead under 5 points), 63 vs 42,
"one in eight" (DVAA's 21/164 = 12.8%, which rounds to 1/8), "we blocked zero" (0 of 164, detection and prevention), and
"held-out … 3 percent … 51" (`captures/holdout-ipi/RESULTS.md`, #142: T3 12/370, DVAA 190/370), and the closing "in our watch-only run, the attacker still got the key" (the recorded observe-mode
egress run in `sentinel/egress/evidence-observe.jsonl` flagged the FAKE AWS key and still forwarded it). If you change a line, change it in `run-demo.sh` and here together.
Our 0 of 164 is on a benign set we also tuned on: say so if asked, and never headline "0% FP".

*Hard stop at 3:00. If running long, cut Beat 6 first, then the second line of Beat 3b. Never cut the "we attacked
ourselves" line: it defuses the hardest Q&A question before a judge asks it.*

---

## Expansion beats (8–10) — the ≈6-minute venture run

> These beats wrap the 3-minute Track 3 core (Beats 1–7, unchanged, live Beat 4b included) for the 5–7 minute 18:00
> slot. They are **presenter-driven from the slides and one terminal command each**, not `run-demo.sh` beats, so
> `run-demo.sh --check-script` does not police their wording — but every number still comes from a committed source
> (`track3a/RESULTS.md`, `demo/slides/VENTURE.md`, `sentinel/scoring/results.json`) and no market figure is invented.
>
> **Close:** drop the final "Thank you." from Beat 7 (dropping a sentence is allowed; don't reword the rest) and
> deliver "Thank you." once at the very end, after Beat 9 (or Beat 10 if you run it).

### Beat 8 — OpsBot / Path A: it generalizes (≈0:35) · Slide 11 · `node track3a/run-demo.mjs`

> "That was the organizers' agent. We also built our own — OpsBot, a support agent with the same lethal trifecta — and attacked it. Undefended, it leaks on both the indirect and the direct attack. The chat proxy alone stops the direct one. Add the egress guard and both are stopped, two of two, with zero false alarms on the benign tasks. No single layer is enough; together they hold. Same unmodified SentinelProxy, a different agent."

*Screen:* Slide 11 (the Path-A layering table) and, in the terminal, `node track3a/run-demo.mjs` (about 2 s; it prints
the matrix). Numbers are the committed `track3a/RESULTS.md`: attacks stopped per stack — undefended 0/2, chat proxy
1/2, chat proxy + egress guard 2/2, hardened-only (mandate) 1/2, hardened + both 2/2; benign false positives 0/2 on
every row. The point to make: no single layer is enough (the chat proxy can't see an injection that arrives inside a
tool result; the mandate can't stop a malicious user turn), but together they stop both attacks with zero benign false
positives — the same architecture finding as the DVAA A/B. **Cut this beat first if running long** (after Beat 10).
Fallback: open `track3a/RESULTS.md` instead of running the command.

### Beat 9 — Ciocca: who pays, how it stands apart, path to launch (≈1:25) · Slide 12

> "As a product, for the Ciocca award: who pays? Teams running agents they can't rebuild — a vendor agent, an open-source one, a legacy internal one — where you can't rewrite the prompt or the tool code, but you can control the network. The budget holder can't ship an agent until security signs off on what it can send out. How we stand apart: classifiers ask whether text looks like an attack, and an attacker can reword it. We ask whether the user authorized the destination, and rewording doesn't change where the data goes. It's the secure web gateway model — a destination allowlist on egress — applied one layer down, to an agent's tool calls. Our path to launch: today, a prototype against the sandbox and our own OpsBot; next, an open-source sidecar that design partners run in observe mode on real traffic; then a paid managed tier for hosted allowlists and alert routing; then SOC integration. Where data actually leaves, we prevent 57 of 71 exfil attempts with zero of 164 legitimate requests blocked; the sandbox's scanner prevents 64 of 71 but blocks 21 of 164."

*Screen:* Slide 12 (the venture slide, from `demo/slides/VENTURE.md`), including the "how it stands apart" table with
the **SWG / SASE egress row**. **No market size, price, or customer name is spoken** (`VENTURE.md` "Do not say"). Always
pair "57 of 71" with the baseline's "64 of 71 at 21 of 164 blocked" in the same breath (done in the line above). The
SWG/SASE line is an analogy for what the egress guard *is* (a destination allowlist), not a claim that it works because
gateways work. This beat is the heart of the venture award — **never cut it.**

### Beat 10 — SOC handoff (≈0:25, only if time) · Slide 12 footer · `scripts/soc-handoff.sh`

> "And if there's time: our alerts don't stop at a dashboard. One offline command hands them to our Track 1 SOC brief, which turns them into a plain-English priority-one analyst brief — the source document, the tool, and the destination — ready for triage. No model key, no network. Thank you."

*Screen:* the terminal, `scripts/soc-handoff.sh` (it prints the brief and writes `.eval/soc-handoff/brief.md`; offline,
Node ≥ 22; merged in PR #86). **Only if time** — this is the first thing to drop when the clock is tight. If you skip
Beat 10, move the closing **"Thank you."** to the end of Beat 9.

---

## Timing budget

Word counts are exact (spoken lines only, counted by whitespace). At 150 wpm.

| Beat | Window | Words | Spoken time |
|---|---|---|---|
| 1 Hook + "deterministic sandbox, no LLM" | 0:00–0:15 | 33 | 13 s |
| 2 Structure + thesis | 0:15–0:35 | 47 | 19 s |
| 3 Exploit (red, recorded) | 0:35–0:50 | 29 | 12 s |
| 3b 8KB evasion (red, recorded) | 0:50–1:04 | 32 | 13 s |
| 4 Block (green, live) | 1:04–1:24 | 37 | 15 s |
| 4b Egress guard (green, LIVE) | 1:24–1:41 | 40 | 16 s |
| 5a Twin (Slide 6 only) | 1:41–1:53 | 26 | 10 s |
| 6 Guest list | 1:53–2:06 | 28 | 11 s |
| 7 Outcome + "we attacked ourselves" + close | 2:06–2:49 | 104 | 42 s |
| **Total** | | **376** | **2:30** of speech; about 2:49 with Enter presses and tab switches |

If you shorten a spoken line, drop whole sentences; don't reword (the runner checks the text).

> **Note on metrics:** the stage reads `sentinel/scoring/results.json`. Figures from the older 29-case
> corpus are stale and must not be used anywhere. **Never hand-type metrics into the slides.**

## Claims used and their sources

Every quoted fact on a slide must appear verbatim in `planning/CITATIONS.md` "Safe slide wording".

- Air Canada, Chevy and Kurtz are **on Slide 2 only**, not spoken. Slide wording: "Air Canada lost a tribunal case over
  its chatbot (Moffatt v. Air Canada, 2024 BCCRT 149)"; "A Chevy dealer's chatbot 'agreed' to sell a 2024 Tahoe for $1"
  (never "sold"); "Each prompt becomes an entry point for the adversary." (George Kurtz, CEO & founder). Don't quote the C$812 figure.
- Hardy, "The Confused Deputy", ACM SIGOPS OSR 22(4):36–38, 1988: **slide 3 footer only**.
- Mechanism (Beat 6): the egress allowlist ("a guest list, not a lie detector") is the one spoken mechanism. Confirmation
  of Payee, the mandate and fail-closed rows stay on Slide 7, unspoken.
- **Don't say** "BEC, the $3 billion-a-year fraud", "lost in court", "sold a Tahoe", "a working slice of Falcon AIDR",
  or any AIDR efficacy number without "up to … (CrowdStrike, internal benchmark)".
