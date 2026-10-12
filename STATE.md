# STATE — living loop state (source of truth; update every iteration)

> This file survives context compaction. Any agent resuming the loop reads GOAL.md + LOOP.md + this.
> Keep it terse and current. Append to the Decision Log; overwrite the Status block.

## Status (overwrite each iteration)
- **As of:** 2026-10-12 ~13:00 PDT. **Submit by 16:00 PDT (target 15:55). Present at 18:00 PDT.** **CODE FREEZE: 15:15 PDT** (moved from 14:30, #39).
- **Phase:** ENDGAME: drain the serial merge queues, then the final rescore at 15:00 and the delivery gate at 15:15.
- **Presenter:** Catherine (c-awad), from her Mac over screen share (#39, #51). Mac: M4 Pro arm64, macOS 26.6.2, Colima,
  stock bash 3.2, Node 26 (moving to node@24). Mac QA issues #58–#61 are routed.
- **Submissions (#63):** (1) **Track 3** = Path A (`track3a/` OpsBot, #62) + Path B (SentinelProxy), ONE submission.
  (2) **Track 1** = Shruti's SOC analyst tool (`track1/`, #64/#68), a separate submission; advisor agents review it every ~30 min.
- **Merged to `main` (41):** #1 #2 #3 #4 #5 #7 #8 #9 #10 #11 #12 #13 #14 #15 #16 #17 #18 #19 #20 #21 #22 #24 #25 #26 #28
  #29 #30 #31 #33 #35 #41 #42 #43 #44 #45 #47 #48 #62 #65 #67 #69. Closed unmerged: #6 (superseded by #7), #27 (folded into T3-fix).
- **Open PRs:**
  | PR | Ticket | Owner | State |
  |---|---|---|---|
  | #56 | T3-fix | MoAlborati (loop) | **Serial merge queue 3** (#62 Track 3A OpsBot already merged; re-gate #56 on fresh main) |
  | #49 → #46 | T5-lens headline → T3-recall | MoAlborati (loop) | **Serial merge queue 2**: #49 first, then #46 |
  | #57 | T12-live egress test isolation | MoAlborati (loop) | Self-merge on green |
  | #50 | T9-fix beat 4 detector credit | MoAlborati (loop) | Self-merge on green |
  | #23 | Orchestrator loop | shrutidoshi94 | To be closed at 13:00 (one orchestrator, #36) |
- **Open needs-human issues:** #40 (pre-public, @MoAlborati by 14:00), #52 (how/where to submit, @MoAlborati by 13:30),
  #54 (Track 3A status, @c-awad by 14:45), #55 (presentation format, @c-awad by 14:30), #66 (demo video, by 15:00),
  #68 (Track 1 agent builds, @shrutidoshi94 by 13:15). Each names an owner, a deadline and a default.
  Mac QA (`chat`): #58 bash ≥4, #59 GNU timeout, #60 Colima tmpdir, #61 Node 26 timing. Chat: #32 (start here), #34.
- **Last green gate:** `scripts/eval.sh gate` per PR. Delivery gate (≥5 clean replays) runs 15:15–15:45 on main AND on Catherine's Mac.

### Schedule (operator, #39; replaces the 11:58 schedule)
| Window (PDT) | Work |
|---|---|
| now–15:00 | Drain merge queues (#56; #49 → #46), #57, #50 |
| **15:00** | **Final rescore** (RESULTS.md); pitch framing decided from it (#38) |
| **15:15** | **CODE FREEZE** |
| 15:15–15:45 | Delivery gate on `main` AND on Catherine's Mac; tag `v1.0-submission` at 15:45 |
| **by 15:55** | **Submit** (deadline 16:00) |
| 16:00–18:00 | Slides and rehearsal |
| **18:00** | **Present** (Catherine, screen share) |

### Honest metrics (353-case corpus: 189 attack / 164 benign; T7-real lenses; final numbers after the 15:00 rescore)
Current `sentinel/scoring/RESULTS.md` on `main`:
| System | Detection | Prevention | Benign FP |
|---|---|---|---|
| SentinelProxy T3 | 63.0% (119/189) | 41.8% (79/189) | **0.0% (0/164)** |
| DVAA baseline | 65.6% | 63.0% | 12.8% (21/164) |
- Pending PRs that change these: **#56 T3-fix** (shadow-review blockers) and **#46 T3-recall**: detection 63.0% → **83.1%**,
  prevention 41.8% → **50.3%**, benign FP stays **0/164**. RESULTS.md is regenerated at the 15:00 rescore.
- T3 catches both cases that evade DVAA's 8 KB scan baseline (2/2, prevented 2/2). DVAA's recall comes with 12.8% benign FP.

## Backlog pointer
See BACKLOG.md. Next: queue 3 (#56; #62 merged), queue 2 (#49 → #46), #57, #50; final rescore 15:00; freeze 15:15; delivery gate; submit.

## Decision Log (append-only, newest first)
- 2026-10-12 ~13:00 PDT — **Schedule change (#39):** submit by 16:00, present at 18:00. Code freeze moves 14:30 → **15:15**.
  Final rescore at **15:00**. Delivery gate **15:15–15:45** on `main` AND on Catherine's Mac. Submit by **15:55**.
  Slides and rehearsal 16:00–18:00. LOOP.md "Endgame policies" updated to match.
- 2026-10-12 — **Presenter and machine (#39, #51):** Catherine (c-awad) presents from her Mac over screen share. Mac: M4 Pro
  arm64, macOS 26.6.2, Colima, stock bash 3.2, Node 26 → move to node@24. Mac QA issues #58–#61 are routed.
- 2026-10-12 — **Tracks (#63):** multiple tracks are allowed, each as its own submission. Track 3 Path A (`track3a/`,
  OpsBot, PR #62) and Path B (SentinelProxy) ship as ONE submission. Track 1 (Shruti, `track1/`, #64/#68) is a separate
  submission, with advisor agents reviewing it every ~30 min.
- 2026-10-12 — **Canonical proxy (#37):** the `.mjs` proxy (#14) is canonical. Consolidation PR #67 (merged, via its steward) retires the #21 `.js` proxy.
- 2026-10-12 — **One orchestrator (#36):** Shruti's loop is off; this loop is the only orchestrator. #23 is closed at 13:00.
- 2026-10-12 — **Pre-public (#40):** no secrets in tree or history. Local paths scrubbed (#44); other-project references
  scrubbed (#48). Shruti's commit email is OK. Benchmark exfil targets kept verbatim (default). Recommendation: squash-publish
  after the hackathon.
- 2026-10-12 — **Pitch framing (#38):** deferred until the 15:00 final rescore. Pure-injection policy = **alert** (not block).
- 2026-10-12 — **Submission (#52):** no submission format found in the DVAA repo. SUBMISSION.md drafted and merged (#69); tag
  `v1.0-submission` planned for 15:45.
- 2026-10-12 — **Process (endgame):** chat intake via issues (#32/#33); 1-minute orchestrator tick ("orchestrator should
  always be active and working"); serial merge queues (queue 2: #49 → #46, queue 3: #56 → #62; #62 merged first); every `needs-human` issue
  names an owner, a deadline and a default. A mock judge review drove the stage fixes (#49, #50, T5-stage).
- 2026-10-12 — **CPU-time timing test fix (in flight; first step #42 merged):** the T3 timing test now bounds CPU time (40 ms), not
  wall clock, because wall-clock timing flaked under parallel gate load. #27's cap/dedupe work is folded into T3-fix.
- 2026-10-12 — **Metric split: detection vs prevention.** Response-side checks are alert-only (T8), so we report
  detection (alert raised) and prevention (request blocked pre-forward) separately, with benign FP as the headline. No blended numbers (#28).
- 2026-10-12 — **Two orchestrators (#36).** A teammate's loop (#23) and this loop were both active. We asked the
  operator in #36 to pick ONE. Until they answer, this loop leaves #23 alone and avoids its files.
- 2026-10-12 — **Serial merge queue:** to stop each merge from breaking the next PR, merges go one at a time, each
  re-gated against fresh main (`scripts/eval.sh gate`): #41 → #35 → #26.
- 2026-10-12 — **1-minute orchestrator tick:** the ~10-minute heartbeat dropped to 1 minute for the endgame (chat,
  PR reviews, CI). "orchestrator should always be active and working".
- 2026-10-12 — **Chat intake via GitHub Issues (#32, PR #33):** humans talk to the loop through `chat`-labelled issues;
  a poller picks them up, and `needs-human` marks operator decisions (CHAT.md).
- 2026-10-12 11:58 PDT — **Endgame decisions (operator).** Operator's direction: "limit scope, our goal is to win the hackathon".
  1. **Deadline 16:00 PDT.** Schedule in the Status block. **Feature freeze 14:30.**
  2. **Merge authority:** a reviewer or merge-steward agent may merge a PR once its reviewer verdict is APPROVE and its tests are green.
     Humans can still review at any time.
  3. **Review-round cap:** at most 2 fix rounds per PR. Anything still open after that goes under "Known limitations" in the PR, then merge.
  4. **T3 scope frozen** to the demo-critical minimum: honeytoken tripwire, destination provenance, full-payload fail-closed
     request-side scan, and T4 verdicts. Everything else in T3 becomes stretch.
  5. **Architecture finding (T8):** DVAA agents execute tools in-process, so the proxy can prevent only request-side (pre-forward)
     attacks. Response-side checks are alert-only. The pitch claim is decided after the egress spike.
  6. **Repo visibility:** judges will get access, and the repo goes public later. Presentation materials and the video come at the end.
- 2026-10-12 — Branch policy: all ticket PRs target `main` from now on. #2, #4 and #5 had merged into stacked base branches, so their content was off `main`; this catch-up PR lands T0b, T0c and T1.
- 2026-10-12 — T1 DONE (PR #5, attempt 2). It captured 3 attack fixtures (RAGBot A/B, RepoBot, FlightBot) and 6 benign ones. Headline pair: RAGBot 7005 ↔ RAGBot-AIM 7014. The optional LegacyBot/SecureBot pair is deferred: it hit a safety stop, and acceptance (≥3 attack fixtures) is already met.
- 2026-10-12 — **Concurrency floor (operator directive):** replaces the "at most 3 implementer agents" cap with
  **minimum 5 concurrent child agents**, all Opus 5.5, each in its own worktree on a disjoint file scope. When fewer than 5
  tickets are unblocked, run tickets stacked on in-review branches plus research, review and test agents. The orchestrator is always
  working and runs a **~10-minute heartbeat** that checks PR reviews and comments (LOOP.md §Parallelism, §How the loop keeps
  running; AGENTS.md; prompts/orchestrator-kickoff.md; BACKLOG parallel-waves note).
- 2026-10-12 — **Worktree rule:** every concurrently running ticket MUST use its own `git worktree` at
  `../<repo>-<ticket>`, and the main checkout is orchestrator-only. Cause: an incident where agents shared the main checkout
  and a commit landed on another agent's branch (LOOP.md §Worktrees, AGENTS.md, all `prompts/*.md`).
- 2026-10-12 — **Cost-waiver line** added to every `prompts/*.md`: the operator has waived cost limits, so child agents ignore COST
  hook messages and finish (cost hooks had cut several T0c research reports short, and many of their citations are unverified).
- 2026-10-12 — **T1 attempt 1 ended DEGRADED:** a safety-classifier stop, plus the build machine's Node 22 is below DVAA's
  required Node ≥24. Re-dispatched with DVAA run **via Docker** instead of the host Node.
- 2026-10-12 — T0c adjacent-knowledge round 2 (`planning/ADJACENT.md` §10, PR stacked on #2): eight more domains plus
  an empirical transfer-cases study. **Framing revised:** matching actor roles is neither necessary nor sufficient. The predictors are a
  comparable choke point and adversary adaptation relative to feedback, and actor roles mainly locate the choke point. Backlog: T3 gains
  the **user-turn mandate** (signed `{tool, destination, max_amount, expires}` from principal turns only), merged with
  destination provenance and per-tool policy into one `policy.json`. T7 gains **per-rule override-rate tracking**
  (CPOE 49–96% overrides, so hard-block a narrow tier, human-only override). New stretch tickets: S10 tool-manifest lockfile + capability
  diff, S11 counterfactual re-plan explainer (MELON, ICML 2025), S12 cross-session campaign correlation.
- 2026-10-12 — T0b adjacent-knowledge analysis (`planning/ADJACENT.md`, PR stacked on #1): a field counts as adjacent
  by structural match (confused-deputy triad, shared data/control channel, choke point, adaptive adversary),
  not surface similarity. Top sources are software injection and BEC; immunology and HACCP are narrative only. Folded the convergent
  deterministic mechanisms into T3/T4/T5/T7 (destination provenance, source→sink rule, canaries + seeded
  fake records, fail-closed, per-tool policy report-only/enforce, cumulative caps, narrative case card,
  benign FP rate as headline metric). Added stretch S5–S9. **Excluded learned behavioral baselines** (no history).
- 2026-10-12 — Model policy set: orchestrator = main Opus 5.5 session (non-implementing); all ticket work
  by child agents dispatched `model: "opus"` (Opus 5.5); degradation/safety-stop → handoff file +
  re-dispatch fresh Opus 5.5, max 2 retries then operator (LOOP.md §Model policy, AGENTS.md).
- 2026-10-12 — GitHub remote set: origin = shrutidoshi94/AIC-X-Crowdstrike-Hackathon (we have WRITE).
  Remote blocker resolved. T0 setup raised as reviewable PR off `t0-goal-loop-setup`.
- 2026-10-12 — Pivoted from "paste-prompt" deliverable to autonomous PR-driven goal loop (operator request).
- 2026-10-12 — Path B locked; SentinelProxy reverse-proxy design chosen; DVAA mapped (see STRATEGY §4).
- 2026-10-12 — 5-agent parallel recon complete; strategy + research docs written.

## Metrics (update as tickets land)
| DoD item | Ticket | PR(s) | Status | Notes |
|---|---|---|---|---|
| 1 Exploit+evasion | T1, T6, T6b | #5, #10, #15, #29, #31 | MERGED | Corpus 353 cases (189/164); #31 fixed exfil labels |
| 2 Detect+block | T2, T3, T3-fix, T3-recall | #14, #21, #24, #41, #42, #67; #56, #46 open | MERGED core; queues 3 (#56) and 2 (#46) | Request-side block only; `.mjs` canonical (#37 → #67) |
| 3 AIDR alert | T4, T10 | #3, #12, #26 | MERGED | #26 wires verdicts → alerts → dashboard |
| 4 Incident graph | T5, T5-lens | #11; #49 open | MERGED; #49 heads queue 2 | Headline Detected/Prevented vs DVAA (mock judge review) |
| 5 Scoring | T7, T7-real | #13, #28 | MERGED | 63.0% / 41.8% / 0 FP now; 83.1% / 50.3% / 0 FP with #46 |
| 6 Secure contrast | T8, spike, T12, T12-live | #16, #18, #22, #45; #57 open | MERGED; #57 self-merge | Response-side alert-only; egress enforced at tool boundary |
| 7 Demo script | T9, T9-fix | #9, #35, #65; #50 open | MERGED; #50 self-merge | Presenter Catherine (Mac); video #66 |
| Track 3A | OpsBot | #62 | MERGED | Same submission as Path B (#63) |
| Submission | docs | #69 | MERGED | Tag `v1.0-submission` at 15:45 |
| Infra | T11, chat | #20, #33 | MERGED | One-command eval + merge gate; Mac QA #58–#61 |
