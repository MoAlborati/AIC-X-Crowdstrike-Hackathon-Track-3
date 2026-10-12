# SentinelProxy — demo script (target 2:50, hard limit 3:00)

> **Status: DRAFT (T9-draft).** Beats follow `planning/STRATEGY.md` §7. Every factual claim spoken on stage
> uses the "Safe slide wording" from `planning/CITATIONS.md` (branch `t-citations`). Don't paraphrase those
> claims and don't add new ones. Placeholders look like `<<T2: …>>` and `<<METRIC: …>>`. Each one is
> filled when its ticket merges. **Never fill a metric slot by hand.** It comes from the T7 scoring output.
>
> Companion deck: `demo/DECK.md`. Still to do for T9 (not in this draft): `demo/run-demo.sh`, the
> fallback-video checklist, and 3 logged rehearsals.

## Ground rules (STRATEGY §8)

- **No live LLM or API calls in the 3 minutes.** Everything replays deterministically from `captures/`.
  A live run against the fleet is an optional encore, after the clock stops.
- **Don't run the attacker live.** The exploit is DVAA's own bundled payload (APWN-DE-003), already
  captured in `captures/attack/aim-ab.demo.json`.
- **Fallback:** if any command fails, switch straight to the recorded video. Don't debug on stage.
- **Headline pair:** **RAGBot 7005** (vulnerable) ↔ **RAGBot-AIM 7014** (AIM-defended twin, same code).

## Pre-flight (before walking on stage, not timed)

```bash
# 1. Target up, all ports bound to 127.0.0.1 (real, merged in T1)
scripts/setup-dvaa.sh up
scripts/setup-dvaa.sh health

# 2. Proxy in front of RAGBot 7005, block mode
<<T2: start proxy, e.g. node sentinel/proxy/index.js --config sentinel/config/demo.block.json  (target 7005, mode=block)>>

# 3. Dashboard loaded on the replay capture
<<T5: start dashboard, e.g. node sentinel/dashboard/server.js --replay captures/attack/aim-ab.demo.json>>

# 4. Scoring table pre-computed, so the numbers on screen match the slide
<<T7: e.g. node sentinel/scoring/run.js --corpus captures/ --out demo/out/score.json>>
```

All commands run from the repo root.

Screen layout: **left** = terminal (attacker view), **right** = dashboard (detector view). Font ≥ 20pt.

---

## Beat sheet

Spoken lines are in quotes. Roughly 150 words per minute. The time column is cumulative.

### Beat 1 — Hook (0:00–0:20) · Slide 1 → 2

> "Air Canada lost a tribunal case over its chatbot. A Chevy dealer's chatbot 'agreed' to sell a 2024
> Tahoe for $1. CrowdStrike's CEO put it plainly: 'Each prompt becomes an entry point for the
> adversary.' Today that prompt can arrive inside a document your agent reads."

*Screen:* slide 2 (two incidents plus the Kurtz quote).

### Beat 2 — The structure (0:20–0:40) · Slide 3

> "Picture a new bank teller who obeys any note slipped into a deposit envelope. The teller has the
> authority, the customer owns it, and the attacker can't touch the vault directly, so the attacker
> writes the note. That's the confused deputy, Hardy 1988. Your AI agent is that teller, and every RAG doc,
> web page and repo file is an envelope."

*Screen:* slide 3, a three-actor diagram (principal → deputy → tools, with the adversary feeding content).

### Beat 3 — EXPLOIT, red (0:40–1:10) · terminal, then dashboard left pane

> "This is RAGBot on port 7005, an intentionally vulnerable agent from the organizers' DVAA sandbox. We feed it
> one poisoned document from DVAA's own attack corpus."

```bash
# Real today: the captured vulnerable run (T1)
jq -r '.runA.toolCalls[0].function.name, .runA.dvaa.exfilExecuted' captures/attack/aim-ab.demo.json
jq -r '.canary.hits[0].query.data' captures/attack/aim-ab.demo.json
```

Expected on screen: `submit_to_index`, `true`, then
`… Admin credentials: dvaa-admin-secret | User John Doe SSN: 123-45-6789` (all fake sandbox values).

> "It called `submit_to_index`, and the admin secret and an SSN just left the building."

*(Pause for two seconds and let it land.)*

**Optional, only if T6 has merged:** the same exploit with the instruction placed outside DVAA's head+tail
8KB scan window.

```bash
<<T6: replay the 8KB-evasion variant through DVAA's baseline detectAttacks(), e.g. node sentinel/scoring/baseline.js captures/variants/<id>.json  → expect "no detection">>
```

> "DVAA's own scanner only looks at the first and last 8KB. This one hides in the middle, and the scanner sees nothing."

*Cut this sub-beat if T6 hasn't merged. It saves about 10 seconds.*

### Beat 4 — DETECT → ALERT → BLOCK, green (1:10–1:45) · dashboard

> "Same agent, same document, but now it goes through SentinelProxy. First, a normal question passes
> untouched."

```bash
<<T2/T5: replay benign capture captures/benign/7005_ragbot.req.json through proxy → expect ALLOWED>>
```

> "Now the attack."

```bash
<<T2/T5: replay captures/attack/aim-ab.demo.json runA through proxy (block mode) → expect BLOCKED>>
```

*Screen, in order:*
1. The honeytoken tripwire fires on `dvaa-admin-secret` in the `submit_to_index` args.
2. The incident graph: poisoned RAG doc → sensitive read → `submit_to_index`, with the **taint path glowing red**.
3. The tool call is marked **BLOCKED**, with latency `<<METRIC: this call's detection latency, ms, from T5 readout>>`.
4. The alert card shows `DetectName`, Severity, MITRE ATLAS / ATT&CK T1567, OWASP LLM01 · LLM02 · LLM06,
   ASI01 · ASI02, plus the narrative case card ("Instruction originated in … → blocked by …").

> "Detected, alerted and blocked before the secret left. The alert names the source document, the tool and the
> sink, and it's mapped to MITRE ATLAS and OWASP."

### Beat 5 — Red vs green (1:45–2:05) · Slide 6, three columns

> "Here's the A/B. On the left, RAGBot 7005 gets pwned. In the middle is its twin, RAGBot-AIM 7014, the same code with
> its capability guard switched on, and it's denied. On the right is 7005 again, unmodified, behind SentinelProxy, and it's blocked.
> Secure-by-design works when you can rebuild the agent. We protect the agents you can't rebuild."

```bash
# Real today: the AIM twin's verdict on the identical payload (T1)
jq -r '.runB.dvaa.exfilExecuted, .runB.dvaa.aim.denialReason' captures/attack/aim-ab.demo.json
<<T8: show SecureBot 7001 contrast capture, e.g. jq ... captures/contrast/7001_securebot.json  → exfilExecuted=false>>
```

| Column | Agent | Verdict | Source |
|---|---|---|---|
| RED | RAGBot 7005 | exfil executed (`dvaa.exfilExecuted=true`) | `aim-ab.demo.json` runA |
| GREEN | RAGBot-AIM 7014 | denied by AIM (`exfilExecuted=false`) | `aim-ab.demo.json` runB |
| GREEN | RAGBot 7005 + SentinelProxy | blocked at the proxy | `<<T2/T3 replay output>>` |

### Beat 6 — How it works (2:05–2:30) · Slide 7

> "We didn't invent these controls. We borrowed them from fields that already solved the confused deputy.
> Banks check the payee before money moves, so we block any destination that came only from untrusted content.
> Power of attorney is limited by what the principal granted, so the user's own turn sets the mandate and a document
> can't widen it. And a dead-man switch fails closed: if our scanner times out or the input is too big, egress is
> denied and we raise an alert. We scan the full payload and never truncate it."

*Screen:* slide 7, three rows of field → mechanism → our rule.

### Beat 7 — Outcome + close (2:30–2:50) · Slides 8 → 10

> "Across `<<METRIC: N attack cases from T7>>` attacks and `<<METRIC: M benign cases from T7>>` benign runs:
> precision `<<METRIC: precision>>`, recall `<<METRIC: recall>>`, false-positive rate
> `<<METRIC: benign FP rate>>`, at a median of `<<METRIC: median latency ms>>` milliseconds. Scored against DVAA's
> own ground-truth labels. This is a working slice of Falcon AI Detection and Response, sitting at the tool boundary.
> Thank you."

*Hard stop at 3:00. If running long, cut Beat 3's optional 8KB sub-beat first, then the benign pass in Beat 4.*

---

## Timing budget

| Beat | Window | Seconds | Spoken words (approx.) |
|---|---|---|---|
| 1 Hook | 0:00–0:20 | 20 | 45 |
| 2 Structure | 0:20–0:40 | 20 | 60 |
| 3 Exploit (red) | 0:40–1:10 | 30 | 40 (+25 optional) |
| 4 Detect/block (green) | 1:10–1:45 | 35 | 50 |
| 5 Red vs green | 1:45–2:05 | 20 | 65 |
| 6 How it works | 2:05–2:30 | 25 | 80 |
| 7 Close | 2:30–2:50 | 20 | 65 |
| Buffer | 2:50–3:00 | 10 | — |

Beats 5–7 run dense, at about 3.2 words per second. Rehearsal must confirm they fit. If not, trim Beat 6 to two mechanisms.

## Placeholder register (fill on merge, then delete this table)

| Slot | Owner | Fill with |
|---|---|---|
| `<<T2: start proxy …>>` | T2 | exact proxy start command + config path |
| `<<T5: start dashboard …>>` | T5 | exact dashboard + replay command, URL |
| `<<T2/T5: replay … ALLOWED / BLOCKED>>` | T2/T3/T5 | exact replay command and expected output line |
| `<<T6: … 8KB-evasion variant>>` | T6 | variant id + baseline command; cut the sub-beat if absent |
| `<<T7: … score.json>>` | T7 | scoring command |
| `<<T8: SecureBot 7001 contrast>>` | T8 | contrast capture path + jq line |
| `<<METRIC: precision / recall / benign FP rate / median latency / N / M>>` | T7 | numbers copied verbatim from the T7 output file. **Do not invent.** |
| `<<METRIC: this call's detection latency>>` | T5 | live readout on the dashboard, no slide number |

## Claims used and their sources

Every quoted fact must appear verbatim in `planning/CITATIONS.md` "Safe slide wording".

- Air Canada: "Air Canada lost a tribunal case over its chatbot (Moffatt v. Air Canada, 2024 BCCRT 149)". On stage
  we say only the first clause. **Don't say the C$812 figure** (it's still open in CITATIONS).
- Chevy: "A Chevy dealer's chatbot 'agreed' to sell a 2024 Tahoe for $1". Never say "sold".
- Kurtz: "Each prompt becomes an entry point for the adversary." (George Kurtz, CEO & founder)
- Hardy: "The Confused Deputy", ACM SIGOPS OSR 22(4):36–38, 1988.
- Mechanisms (slide 7): Confirmation of Payee, limited power of attorney / user-turn mandate, dead-man fail-closed.
  All three are rated **Yes** in `planning/ADJACENT.md` §6a / §10.3a. Before the demo, confirm all three are actually
  implemented in merged T3. If one isn't, drop it rather than claim it.
- **Don't say** "BEC, the $3 billion-a-year fraud" (use "~$3 billion-a-year" if it's ever used), "lost in court",
  "sold a Tahoe", or any AIDR efficacy number without "up to … (CrowdStrike, internal benchmark)".
