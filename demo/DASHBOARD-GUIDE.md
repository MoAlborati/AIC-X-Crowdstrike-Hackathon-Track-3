# DASHBOARD-GUIDE — presenting from the Tourniquet stage dashboard

Presenter walkthrough for the **frozen** T5 dashboard (`sentinel/dashboard`, `v1.0-submission`). Catherine drives
this at 18:00. **Docs only — the dashboard code is frozen; this guide never changes it.**

What it is in one line: a **deterministic replay** of recorded DVAA captures. The top bar says it out loud —
*"Recorded DVAA captures, replayed deterministically. No live LLM calls."* The *blocks* it shows were produced by the
real Tourniquet detectors over real traffic; the dashboard just re-draws them. It binds **127.0.0.1 only**.

Jump to: [1 Start/stop/reset](#1-start-stop-reset) · [2 The four stage captures](#2-the-four-stage-captures) ·
[3 Lenses & headline tiles](#3-detection-vs-prevention--the-headline-tiles) · [4 Beat-by-beat + Q&A](#4-what-to-click-per-beat--qa) ·
[5 Reading one alert](#5-reading-one-alert-aidr-shaped) · [6 Gotchas](#6-gotchas) · [7 Projector tips](#7-projector-tips)

---

## 1. Start / stop / reset

| Action | Command | Notes |
|---|---|---|
| **Start** | `scripts/eval.sh dashboard` | Serves `http://127.0.0.1:9100/`. Prints `open: …`, the log path `.eval/dashboard.log`, and the stop command. Override the port with `EVAL_DASHBOARD_PORT=9101 …`. |
| **Start (during the demo)** | `demo/run-demo.sh` starts it for you | Don't start it by hand as well. |
| **Stop** | `scripts/eval.sh dashboard-stop` | Stops only the dashboard eval.sh started (by its pid file). |
| **Reset the numbers** | `rm -rf .eval/score` | See below. |

**Finding the real port (fallback).** The demo wants :9100. If :9100 is busy, `run-demo.sh` scans the next ports
(default 20 above it) and **moves** the dashboard. It then prints the real URL everywhere and the closing Summary ends:

```
demo run clean — no failing beats · dashboard http://127.0.0.1:<port>/
```

plus a warning line: *"dashboard port 9100 was busy: the dashboard is on :<port>, so use the links printed above."*
**Always use the port the Summary prints**, not 9100 from memory. If no port starts, the run **FAILS** — it never says
"clean" without a dashboard.

**`rm -rf .eval/score` — committed vs re-scored numbers.** When a `score` run has written `.eval/score/results.json`,
`eval.sh dashboard` shows *those* freshly-rescored numbers. Delete `.eval/score` and the dashboard falls back to the
**committed** `sentinel/scoring/results.json` — the submission numbers (67.7 / 41.8 / 0-of-164). Do this before the
final dry run so the tiles match the slides and a rescored p95 can't drift.

---

## 2. The four stage captures

Add **`?stage=1`** to any URL for **stage mode**: the headline stat tiles and the replay-warning banners are hidden,
the incident graph is zoomed up for the projector, and the Capture dropdown lists **only these four runs, in demo
order** (a missing one stays listed but disabled with `⚠ … (missing)` — never silently dropped).

Deep link shape: `…/?stage=1&capture=<key>&step=last`. `capture=` takes the **stage key** below (a capture id or
legacy `?id=` also works); `step=last` opens on the finished graph; `step=<n>` is 1-based. The pre-opened tabs use
exactly these:

| # | Key (`capture=`) | Deep link | Underlying capture | What it shows |
|---|---|---|---|---|
| 1 | `vulnerable` | `/?stage=1&capture=vulnerable&step=last` | `attack/aim-ab.demo` run `runA` | RAGBot :7005 **with no guard**: the poisoned doc wins, data leaves the sandbox. 6 **real T3** findings, all `Detected · post-execution (alert-only)` — the detector saw it, but this run went straight to DVAA so nothing was blocked. |
| 2 | `aim-twin` | `/?stage=1&capture=aim-twin&step=last` | `attack/aim-ab.demo` run `runB` | Same agent code, **guard on** (RAGBot-AIM :7014). The exfil call is **denied** by the capability grant; the Twin panel contrasts it against #1 side by side (AIM trust score 18). |
| 3 | `proxy-blocked` | `/?stage=1&capture=proxy-blocked&step=last` | `stage/proxy-blocked-t3` run `run` | **Tourniquet, request side.** 2× `IndirectPromptInjection` (High 70), disposition **`Blocked · pre-forward`** — refused *before the agent saw the request*. Alerts are **embedded in the capture** (a real Tourniquet run). |
| 4 | `egress-blocked` | `/?stage=1&capture=egress-blocked&step=last` | `stage/egress-blocked-t12` run `run` | **Tourniquet, tool boundary.** 3 alerts, all **`Blocked · egress (denied before send)`**: `HoneytokenExfiltrationAttempt` (Critical 95) and `NonAllowlistedEgressDestination` (Medium 55). The attacker received nothing. |

The demo walks **1 → 2 → 3 → 4**: broken, then the same attack stopped at each of our two enforcement points.

---

## 3. Detection vs prevention — the headline tiles

These are the three big tiles on the **full** view (drop `?stage=1`). They come from T7 scoring (`/api/scoring`).
**Pair every number with DVAA's own baseline** — the dashboard already prints the pair under each tile:

| Tile | Tourniquet | DVAA baseline | Benign false positives |
|---|---|---|---|
| **Detected** — *any finding fired* | **67.7%** | DVAA 65.6% | **0.0% (0 / 164)** vs DVAA 12.8% |
| **Prevented** — *blocked pre-forward or reply withheld* | **41.8%** | DVAA 63.0% | **0.0% (0 / 164)** vs DVAA 12.8% |
| **In-detector latency** — *median per case, detector only* | **0.094 ms** (p95 0.495 ms) | DVAA median 0.014 ms | — |

**The two lenses are different questions.** *Detected* = did **any** finding fire (alert-only counts). *Prevented* =
did Tourniquet **actually stop it** — a request blocked pre-forward, or the reply withheld — a strict subset of
*Detected*.

**Honest headline wording (say it this way):**
> "Tourniquet detects about two-thirds of attacks and prevents four-in-ten of them — with **zero false positives
> across 164 benign cases**. DVAA's own baseline prevents more, but only by blocking one in eight legitimate requests
> too."

- Don't claim prevention beats DVAA — it doesn't (41.8% vs 63%), **on purpose**: Tourniquet is fail-safe and only
  blocks what it is sure of. The structural win is the **clean benign corpus (0/164)** against DVAA's 12.8%.
- *Prevented* is lower than *Detected* because the response-side honeytoken findings are **alert-only** (DVAA runs
  tools in-process, so only the request side and the egress boundary can prevent — see Beat 4/4b).

---

## 4. What to click per beat + Q&A

The three/four tabs are pre-opened at `step=last`, so each beat is **"switch tab, point, say the line."** Nothing to
click to make the block appear. The quoted lines live in `demo/SCRIPT.md` / `demo/PRESENTER.md` — this guide only says
*where to point*.

| Beat | Tab | Point at | One sentence |
|---|---|---|---|
| 3 Vulnerable | `vulnerable` | the red taint path into the **sink** node; the feed's Critical honeytoken cards marked *post-execution* | "No guard — the poisoned document makes it send the secret, and we only get to watch." |
| (3b AIM twin) | `aim-twin` | the **Twin panel**: Unprotected *vs* AIM-protected, `✖ data left` vs `✔ action denied` | "Same agent, capability grant on — the call is denied." |
| 4 Proxy block | `proxy-blocked` | the feed card: **`Blocked · pre-forward`**, rule *inbound.exfil_instruction* | "Behind Tourniquet the request is refused before the agent ever sees it." |
| 4b Egress block | `egress-blocked` | the three **`Blocked · egress`** cards; the hashed destinations | "And at the tool boundary the exfil call is denied before it leaves — the attacker gets nothing." |

**Stepping through a replay** (if you leave `step=last`): `→ / ←` next/prev, `Home / End` first/last, `Space`
play-pause, or click any row in the right-hand timeline. The URL updates as you step, so it stays a shareable link.

**Q&A — where the answer is on screen:**

- **"Is this live?"** → No; the top bar says *"Recorded… replayed deterministically. No live LLM calls."* But the
  blocks are **real detector output** — the alert-source line under the feed reads *"embedded in capture (live
  Tourniquet run)"* for beats 4/4b.
- **"Is it just keyword matching?"** → No. Open a card's **Detection layers** table (6 layers for the injection
  alerts) and the **Case card** chain: *Originated in* (untrusted doc) → *Influenced* (the tool call) → *Decided by
  rule*. It combines **provenance + honeytoken match + destination allowlist**, not one keyword. Point at the taint
  path, not a highlighted word.
- **"What about the held-out losses?"** → Be honest: on held-out attacks **14 of 16** hand-written paraphrases were
  detected, but on an independent reviewer's 6 further paraphrases only **1** — recall on novel phrasings is limited.
  Held-out benign: **1/32** blocked (a security memo that *quotes* an injection phrase) and 4/32 alert without
  blocking. Full detail in `demo/QA-PREP.md` and `sentinel/scoring/RESULTS.md`.
- **"Two enforcement points?"** → (1) **Request side** — `proxy-blocked`, refused pre-forward before the agent reads
  the poisoned doc. (2) **Tool boundary / egress** — `egress-blocked`, the agent's outbound call denied before send.
  Two independent chances to stop the bleed; response-side detector checks are **alert-only**.
- **"Where do these alerts go?"** → the **⧉ Copy alert JSON** button on each card exports a T4-validated
  `sentinel.alert/1.0.0` (ATLAS/OWASP tags, redacted) — a ready SOC ticket.

---

## 5. Reading one alert (AIDR-shaped)

Use the top card in **`egress-blocked`** — the `HoneytokenExfiltrationAttempt`. Read a card top to bottom:

- **Severity badge** — `⛔ Critical 95`. (Colour band: Critical ≥90, Serious ≥70, Warning ≥50, Low below.)
- **DetectName** — `HoneytokenExfiltrationAttempt` (the injection cards are `IndirectPromptInjection`;
  the allowlist card is `NonAllowlistedEgressDestination`).
- **Disposition** — **`Blocked · egress (denied before send)`**. (Beat 3 shows `Detected · post-execution
  (alert-only)`; Beat 4 shows `Blocked · pre-forward`.)
- **Latency** — a per-alert ms figure. **Don't read it aloud** (see Gotchas).
- **Case card** — a plain-English narrative, then the chain: **Originated in** the RAGBot agent turn → **Influenced**
  the `egress.http.GET(…)` call → **Decided by rule** `egress.honeytoken_match`.
- **Detection layers** — the layer/rule/fired/ms table (this alert fired through 3 layers); shows exactly which
  checks ran.
- **Taint path** — the hop list the graph draws in red (truncated hops are shown as `⋯ N omitted`, never hidden).
- **Tags footer** — ATLAS `AML.T0086 / T0057 / T0051.001`, OWASP-LLM `LLM02/LLM01/LLM06`, Agentic `ASI01/ASI02`,
  `OASB-1:data-exfiltration`, and the **sink** tag (destination hashed, e.g. `host[sha256=…]` — redaction, not a bug).

---

## 6. Gotchas

- **Never read the latency tile aloud.** The re-scored p95 drifts run to run. The script says **"median under a tenth
  of a millisecond."** Say that, not the digits.
- **Port busy.** If `eval.sh dashboard` says *"port 9100 is already in use by another process"*, run the printed fix:
  `EVAL_DASHBOARD_PORT=9101 scripts/eval.sh dashboard`. Inside `run-demo.sh` the move is automatic — use the port the
  Summary prints.
- **A tab shows stale data.** Reload the tab (the server sends `no-store`, so a plain refresh is enough). If numbers
  look wrong, you're likely seeing a rescored `.eval/score` — `rm -rf .eval/score` and restart to get the committed
  numbers back.
- **A capture is missing.** In stage mode a missing entry shows `⚠ … (missing)` disabled plus a red banner naming what
  was tried — it is never silently swapped for something else. If a stage tab is blank, re-run the dry run so
  `run-demo.sh` rebuilds `.eval/stage`; don't improvise a different capture on stage.
- **Theme** resets per browser only; the `◐` toggle persists in `localStorage`. On a fresh profile it follows the OS.

---

## 7. Projector tips

- **Use stage mode (`?stage=1`).** It hides the stat tiles and warnings and gives the incident graph more room
  (graph zoom floor 0.8), so the taint path reads from the back row.
- **Pre-open the tabs at their last step**, in beat order, on the port the runner printed:
  `vulnerable` → `proxy-blocked` → `egress-blocked` (and `aim-twin` if you cover Beat 3b). Then the demo is tab-switching.
- **Dark theme** (`◐`) on the projector; terminal **18 pt**, full height; terminal left, dashboard right.
- Share the **whole screen** at **1920×1080** so you can switch terminal ↔ browser ↔ slides.
- If anything misbehaves on stage, **switch to the fallback video** — don't debug the dashboard live.

---

See also: [`PRESENTER.md`](PRESENTER.md) (run-of-show) · [`QA-PREP.md`](QA-PREP.md) (judge answers) ·
[`SCRIPT.md`](SCRIPT.md) (the spoken lines). Numbers source: `sentinel/scoring/results.json` /
`sentinel/scoring/RESULTS.md`.
