# REHEARSAL — SentinelProxy demo (ticket T9)

How we rehearse `demo/SCRIPT.md` to a clean sub-3-minute run, and the delivery-gate evidence that the
deterministic replay is not a lucky one-off. Driver: `demo/run-demo.sh` (interactive, or `--auto`).

> **Defensive, authorized context.** This rehearses a defensive guardrail against DVAA, the organizers'
> intentionally-vulnerable training sandbox, on localhost only (CrowdStrike × SCU hackathon, Track 3).

---

## 1. Pre-demo checklist (run once, before the talk — not on the stage clock)

**Environment**
- [ ] `scripts/eval.sh doctor` is all green (Node ≥24 via nvm, Docker, pinned DVAA checkout, fleet health).
- [ ] DVAA fleet up on 127.0.0.1 only: `scripts/eval.sh up` (or confirm `curl 127.0.0.1:9000/stats` responds).
      Confirm **no** published port is on a non-loopback address (`scripts/eval.sh doctor` checks this).
- [ ] T5 dashboard reachable: `scripts/eval.sh dashboard` → http://127.0.0.1:9100/ shows ≥1 capture.
- [ ] T7 scoring runs clean: `scripts/eval.sh score` exits 0; note the `results.json` numbers for the slide.
- [ ] One full `demo/run-demo.sh --auto` run is clean (summary: "demo run clean — no failing beats").

**Content / wording**
- [ ] Every spoken fact matches `planning/CITATIONS.md` "Safe slide wording" (don't paraphrase, don't add).
- [ ] `<<METRIC:>>` slots filled **verbatim** from `.eval/score/results.json` — never hand-typed.
      (Headline row is "awaiting T3" until the detector merges; show baselines only until then.)
- [ ] Mechanisms on slide 7 (Confirmation of Payee / limited-mandate / dead-man fail-closed) are each
      actually implemented in merged T3 — drop any that isn't rather than claim it.

**Screen / logistics**
- [ ] Left = terminal (attacker view), right = dashboard (detector view). Font ≥ 20pt.
- [ ] Interactive mode advances on Enter; know the beat order cold.
- [ ] Laptop on power, notifications silenced, network only to localhost.

**Fallback video (record BEFORE the session; switch to it if any command fails — do not debug on stage)**
- [ ] Recorded a clean `demo/run-demo.sh --auto` screen capture end-to-end (terminal + dashboard).
- [ ] Audio narration present, or the deck narration is memorized over the silent capture.
- [ ] Video is ≤ 3:00, named `demo/fallback-demo.mp4` (gitignored; stored on the demo laptop + a USB key).
- [ ] Verified it plays offline on the demo laptop with the projector resolution.
- [ ] One person owns "cut to video" and can trigger it within 3 seconds of a failure.

---

## Delivery gate — one command (`scripts/delivery-gate.sh`)

**Delivery gate 15:15–15:45 on main + Catherine's Mac.** Run it on a clean checkout of `main`, on the build
host AND on Catherine's Mac (stock bash 3.2, Colima, node@24); both must end `VERDICT: PASS`.

```bash
git checkout main && git pull
DG_HOST_LABEL="Catherine's Mac" scripts/delivery-gate.sh     # exit 0 = PASS; anything else = do not ship
```

It runs, in order: `scripts/eval.sh doctor` → `up` → `all` → `demo/run-demo.sh --check-script` (when
present) → `demo/run-demo.sh --auto` ×5 → `scripts/egress-demo.sh both` (on a unique
`EGRESS_PROJECT`/`EGRESS_NET`) → `scripts/eval.sh track3a` (when present). Each step's log goes to
`.eval/delivery-<UTC timestamp>/`; it prints a step | result | duration | log table and appends a dated
entry (machine, bash, node, docker context, git SHA) below. A missing component prints `MISSING: <x>`
(required scripts fail the gate; optional ones fail it only with `DG_STRICT=1`). Knobs: `DG_DEMO_RUNS`,
`DG_DEMO_ARGS` (default `--no-dvaa`, so replays don't stop the fleet `up` started), `DG_STEP_TIMEOUT`,
`DG_NO_RECORD=1`. The script writes the entry into this file; commit it as the gate's evidence.

### Delivery-gate command log

<!-- delivery-gate-log:start — scripts/delivery-gate.sh inserts entries above the end marker -->
#### 2026-10-12T20:17Z — PASS — `ca5294551c77` on build host (WSL2 Linux)
- Machine: `Linux x86_64` · bash 3.2.57(2)-release · node v22.22.3 · docker context `default` · branch `delivery-gate`
- Logs: `.eval/delivery-20261012T201502Z/`

| Step | Result | Duration | Log |
|---|---|---|---|
| eval.sh doctor | PASS | 0s | .eval/delivery-20261012T201502Z/eval-doctor.log |
| eval.sh up | PASS | 1s | .eval/delivery-20261012T201502Z/eval-up.log |
| eval.sh all | PASS | 90s | .eval/delivery-20261012T201502Z/eval-all.log |
| run-demo.sh --check-script | MISSING | - | - |
| run-demo.sh --auto #1 | PASS | 2s | .eval/delivery-20261012T201502Z/demo-auto-1.log |
| run-demo.sh --auto #2 | PASS | 2s | .eval/delivery-20261012T201502Z/demo-auto-2.log |
| run-demo.sh --auto #3 | PASS | 3s | .eval/delivery-20261012T201502Z/demo-auto-3.log |
| run-demo.sh --auto #4 | PASS | 2s | .eval/delivery-20261012T201502Z/demo-auto-4.log |
| run-demo.sh --auto #5 | PASS | 3s | .eval/delivery-20261012T201502Z/demo-auto-5.log |
| egress-demo.sh both | PASS | 41s | .eval/delivery-20261012T201502Z/egress-both.log |
| eval.sh track3a | MISSING | - | - |

<!-- delivery-gate-log:end -->

---

## 2. Timing log — 3 rehearsals

Target 2:50, hard limit 3:00. Record each beat's **actual** seconds against the SCRIPT budget; note what
broke and what you changed. If Beats 5–7 overrun, trim per SCRIPT: cut Beat 3's optional 8KB sub-beat
first, then the benign pass in Beat 4, then drop one mechanism in Beat 6.

| Beat | Budget (s) | Rehearsal 1 | Rehearsal 2 | Rehearsal 3 |
|---|---|---|---|---|
| 1 Hook | 20 | ___ | ___ | ___ |
| 2 Structure | 20 | ___ | ___ | ___ |
| 3 Exploit (red) | 20 | ___ | ___ | ___ |
| 3b 8KB evasion (red, DoD 1) | 20 | ___ | ___ | ___ |
| 4 Detect/block (green) | 30 | ___ | ___ | ___ |
| 5 Red vs green | 15 | ___ | ___ | ___ |
| 6 How it works | 25 | ___ | ___ | ___ |
| 7 Close | 20 | ___ | ___ | ___ |
| **Total** | **≤ 170 (buffer to 180)** | ___ | ___ | ___ |

> The 8KB-evasion beat (3b) is DoD item 1 — never cut it. If over time, cut the benign pass in Beat 4,
> then trim Beat 6 to two mechanisms.

**Rehearsal 1** — date/time: ________  presenter: ________
- Total time: ____   Under 3:00? [ ] yes [ ] no
- What broke / felt rough: ______________________________________________
- Fix applied: __________________________________________________________

**Rehearsal 2** — date/time: ________  presenter: ________
- Total time: ____   Under 3:00? [ ] yes [ ] no
- What broke / felt rough: ______________________________________________
- Fix applied: __________________________________________________________

**Rehearsal 3** — date/time: ________  presenter: ________
- Total time: ____   Under 3:00? [ ] yes [ ] no
- What broke / felt rough: ______________________________________________
- Fix applied: __________________________________________________________

> Rehearsals 1–3 are stage run-throughs with narration + projector, logged by a human. They are distinct
> from the §3 machine replays (which prove the driver is deterministic, not that the talk fits the clock).

---

## 3. Delivery-gate log — ≥5 consecutive clean replays

`gates/delivery-gate.md` (hackathon-scaled) requires **≥5 consecutive clean `demo/run-demo.sh` replays**,
no errors, no nondeterministic variance, on the data-rich environment. Record each here and in STATE.md.

**Environment for this log**
- Machine: build host (WSL2 Linux); Node v24.16.0 (nvm) for dashboard + scoring.
- Data-rich: real `captures/` corpus — dashboard served 33 replay captures; T7 scored 29 cases
  (17 attack, 12 benign, incl. the >8KB EVA-POS-MIDDLE evasion fixture). DVAA fleet was also up
  (22/22 ports healthy per `doctor`); replays used `--no-dvaa` so as not to stop the shared fleet.
- Command: `demo/run-demo.sh --auto --no-dvaa`.
- **All six core beats exercised live and PASS** (nothing NOT-YET-MERGED): doctor preflight, dashboard
  (T5/#11), exploit + AIM twin (T1), request-side proxy block (T2/#14/#21), egress guard (T12/#18),
  scoring (T7/#13). T7 headline is live now that the T3 detector (#24) is merged:
  precision 100.0% · recall 88.2% · benign FP 0.0% · median 0.243 ms.

| Replay | Date/time (UTC) | Exit | Duration | Beats PASS | Failing | Result |
|---|---|---|---|---|---|---|
| 1 | 2026-10-12T19:22Z | 0 | 3s | 6/6 | 0 | CLEAN |
| 2 | 2026-10-12T19:22Z | 0 | 3s | 6/6 | 0 | CLEAN |
| 3 | 2026-10-12T19:22Z | 0 | 4s | 6/6 | 0 | CLEAN |
| 4 | 2026-10-12T19:22Z | 0 | 3s | 6/6 | 0 | CLEAN |
| 5 | 2026-10-12T19:22Z | 0 | 4s | 6/6 | 0 | CLEAN |

**Verdict (this pass): PASS** — 5/5 consecutive clean replays, exit 0, 6/6 beats PASS each, no variance.

> An earlier pass (19:17Z, before T2/T12/T3 landed) was also 5/5 clean with the proxy/egress beats
> correctly reporting NOT YET MERGED. Re-run this gate after any further corpus/detector change so the
> T7 headline metrics on the slide stay in sync with `.eval/score/results.json`. Reproduce:
> ```bash
> for i in 1 2 3 4 5; do demo/run-demo.sh --auto --no-dvaa || echo "replay $i FAILED"; done
> ```
