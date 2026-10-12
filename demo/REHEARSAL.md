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

**Environment for this log** (pass 3, 2026-10-12T19:43Z, branch `t9-beat4-fix` on origin/main `e0e5920`)
- Machine: build host (WSL2 Linux); Node v22.22.3.
- Data-rich: the dashboard served **357 replay captures**; T7 scored the full corpus. The live DVAA fleet
  `dvaa-t1` was up, **22/22 ports healthy** per `doctor`. The runner detected the already-up fleet and did not
  stop it on teardown.
- Command: `EVAL_DASHBOARD_PORT=9107 demo/run-demo.sh --auto` (full mode, live fleet, no `--no-dvaa`).
  Port 9107 was used because 9100 was held by another session's dashboard. On 9100 the dashboard preflight
  reports FAIL/WARN by design.
- **Beat 4 evidence re-recorded** with the shipped post-#41 CLI (`demo/record-beat4.sh`): block mode, shipped
  `sentinel/config/sentinel.config.json`, live RAGBot 7005, request sent by DVAA's own `demo aim-ab`. Inspectors
  registered: `[substring, sentinel-t3]`. **Blocking detector: `sentinel-t3` only**, reasons
  `exfil_instruction_inbound`, `injection_markers`, `payee_not_confirmed`. The substring inspector produced no verdict,
  because the shipped config has no `flagSubstrings`. Beat 4 now fails if the capture's detector or reason set
  ever differs from the spoken credit. This guard was proven RED on the old T8 substring capture and GREEN on the
  new one.
- Every beat PASS, nothing NOT YET MERGED: doctor, DVAA, dashboard, exploit (2), 8KB evasion (2), AIM twin,
  proxy block (T3), egress guard, scoring, dashboard stop. T7 headline at this pass (copied from the run, not
  invented): detection recall 63.0% · prevention recall 41.8% · benign FP 0.0% · precision 100.0% · median 0.081 ms.

| Replay | Date/time (UTC) | Exit | Duration | Summary rows PASS | FAIL / WARN / NYM | Result |
|---|---|---|---|---|---|---|
| 1 | 2026-10-12T19:43:18Z | 0 | 2s | 12/12 | 0 / 0 / 0 | CLEAN |
| 2 | 2026-10-12T19:43:20Z | 0 | 2s | 12/12 | 0 / 0 / 0 | CLEAN |
| 3 | 2026-10-12T19:43:22Z | 0 | 2s | 12/12 | 0 / 0 / 0 | CLEAN |
| 4 | 2026-10-12T19:43:25Z | 0 | 2s | 12/12 | 0 / 0 / 0 | CLEAN |
| 5 | 2026-10-12T19:43:27Z | 0 | 2s | 12/12 | 0 / 0 / 0 | CLEAN |

**Verdict (this pass): PASS.** 5/5 consecutive clean replays, exit 0. The Beat 4 output was byte-identical
across all 5 (same md5), so there was no variance.

> Pass 2 (19:22Z, `--no-dvaa`) was also 5/5 clean, but its Beat 4 credited T3 for a capture whose
> blocking detector was the T2 substring inspector (PR #35 review). Pass 3 above supersedes it.
> An earlier pass (19:17Z, before T2/T12/T3 landed) was also 5/5 clean with the proxy/egress beats
> correctly reporting NOT YET MERGED. Re-run this gate after any further corpus/detector change so the
> T7 headline metrics on the slide stay in sync with `.eval/score/results.json`. Reproduce:
> ```bash
> demo/record-beat4.sh          # optional: re-record Beat 4 from live DVAA with the shipped CLI
> for i in 1 2 3 4 5; do demo/run-demo.sh --auto || echo "replay $i FAILED"; done
> ```
