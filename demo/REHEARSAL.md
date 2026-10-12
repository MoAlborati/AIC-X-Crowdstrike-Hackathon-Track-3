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
- [ ] `sentinel/scoring/results.json` is current (regenerate with `scripts/eval.sh score` only after a corpus or
      detector change, and commit it). Beat 3b and Beat 7 read it.
- [ ] One full `demo/run-demo.sh --auto` run is clean (summary: "demo run clean — no failing beats").

**Content / wording**
- [ ] Every spoken fact matches `planning/CITATIONS.md` "Safe slide wording" (don't paraphrase, don't add).
- [ ] `<<METRIC:>>` slots filled **verbatim** from `sentinel/scoring/results.json`, never hand-typed. Show detection
      and prevention recall for T3 **and** DVAA's baseline, with FP. Say "8KB evasion: 2/2 fixtures", never a blanket
      "beats baseline". Quote one latency figure: "in-detector ~0.5 ms".
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

**Environment for this log** (pass 3, 2026-10-12T19:54Z, branch `t9-beat4-fix` on origin/main `6c4fdc7`)
- Machine: build host (WSL2 Linux); Node v22.22.3.
- Data-rich: the dashboard served **357 replay captures**. Metrics come from `sentinel/scoring/results.json`
  (**353 cases: 189 attack + 164 benign**). The live DVAA fleet `dvaa-t1` was up, **22/22 ports healthy** per
  `doctor`. The runner detected the already-up fleet and did not stop it.
- Command: `EVAL_DASHBOARD_PORT=9107 demo/run-demo.sh --auto` (full mode, live fleet). Port 9107 was used because
  9100 was held by another session's dashboard; on a held port the dashboard preflight reports FAIL/WARN by design.
- **Beat 4 is live and credits T3.** The runner starts the shipped CLI (`node sentinel/proxy/cli.mjs`, block mode,
  inspectors `[substring, sentinel-t3]`) on an ephemeral loopback port in front of 7005. The benign question got
  **200** (forwarded). DVAA's aim-ab request body got **403**, with verdict `sentinel-t3` and reasons
  `exfil_instruction_inbound`, `injection_markers`, `payee_not_confirmed`, read from the live proxy's own log.
  The recording `captures/contrast/runs/proxy-block.*` was re-captured with the shipped CLI against live DVAA
  (`run-meta.json`: `inspector: detector:sentinel-t3`, not stand-in). Its T4 alert (`proxy-block.t4-alerts.json`,
  T10 pipeline `convert`) is `IndirectPromptInjection` / `inbound.exfil_instruction`. Beat 4 fails if the live log
  or the recording names a different detector or reason set. That guard was proven RED on the old stand-in
  (`substring`) capture and GREEN on the new one. The fallback path (7005 unreachable -> WARN + recording) was
  exercised once separately.
- **Beat 4b** uses `sentinel/egress/` (#45). It shows the deny decisions (`evidence-block.jsonl`) and the ground
  truth from a live `scripts/egress-demo.sh block` run (`demo/captures/egress-demo-block.txt`): **0 canary hits**,
  and RAGBot 7005 and RepoBot 7022 are both PREVENTED. The `api.oa2a.org` deny is DVAA's startup telemetry.
- Beat order: 3, 3b, 4, 4b, 5a, 7. Beat 7 prints two headline rows from `results.json` (T3 vs DVAA baseline):
  detection 63.0% / FP 0.0% vs 65.6% / 12.8%; prevention 41.8% / FP 0.0% vs 63.0% / 12.8%; 8KB evasion 2/2;
  in-detector p95 0.38 ms.

| Replay | Date/time (UTC) | Exit | Duration | Summary rows PASS | FAIL / WARN / NYM | Live 200/403 | Result |
|---|---|---|---|---|---|---|---|
| 1 | 2026-10-12T19:54:03Z | 0 | 3s | 16/16 | 0 / 0 / 0 | yes | CLEAN |
| 2 | 2026-10-12T19:54:06Z | 0 | 3s | 16/16 | 0 / 0 / 0 | yes | CLEAN |
| 3 | 2026-10-12T19:54:09Z | 0 | 3s | 16/16 | 0 / 0 / 0 | yes | CLEAN |
| 4 | 2026-10-12T19:54:12Z | 0 | 2s | 16/16 | 0 / 0 / 0 | yes | CLEAN |
| 5 | 2026-10-12T19:54:14Z | 0 | 2s | 16/16 | 0 / 0 / 0 | yes | CLEAN |

**Verdict (this pass): PASS.** 5/5 consecutive clean replays, exit 0. Beat output from Beat 3 to teardown was
identical across all 5 (same md5 after normalizing the ephemeral proxy port), so there was no variance. No orphan
proxy process was left afterwards.

> Pass 2 (19:22Z, `--no-dvaa`) was also 5/5 clean, but its Beat 4 credited T3 for a capture whose
> blocking detector was the T2 substring inspector (PR #35 review). Its metrics (29-case corpus) are stale.
> Pass 3 above supersedes it.
> An earlier pass (19:17Z, before T2/T12/T3 landed) was also 5/5 clean with the proxy/egress beats
> correctly reporting NOT YET MERGED. Re-run this gate after any further corpus/detector change so the
> T7 headline metrics on the slide stay in sync with `sentinel/scoring/results.json`. Reproduce:
> ```bash
> captures/contrast/run-contrast.sh   # optional: re-record Beat 4 / slide 6 from live DVAA with the shipped CLI
> scripts/egress-demo.sh block        # optional: re-record the Beat 4b ground truth
> for i in 1 2 3 4 5; do demo/run-demo.sh --auto || echo "replay $i FAILED"; done
> ```
