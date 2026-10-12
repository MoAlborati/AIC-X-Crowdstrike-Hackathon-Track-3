# STATE — living loop state (source of truth; update every iteration)

> This file survives context compaction. Any agent resuming the loop reads GOAL.md + LOOP.md + this.
> Keep it terse and current. Append to the Decision Log; overwrite the Status block.

## Status (overwrite each iteration)
- **As of:** 2026-10-12 12:35 PDT. **Deadline: 16:00 PDT.** **FEATURE FREEZE: 14:30 PDT.**
- **Phase:** ENDGAME: landing T3 follow-ups, T10, T9 runner and real metrics before the freeze.
- **Merged to `main` (28):** #1 #2 #3 #4 #5 #7 #8 #9 #10 #11 #12 #13 #14 #15 #16 #17 #18 #19 #20 #21 #22 #24 #25
  #29 #30 #33 #41 #42. #6 was closed (superseded by #7).
- **Open PRs:**
  | PR | Ticket | Owner | State |
  |---|---|---|---|
  | #41 → #35 → #26 | T2-fix / T9 runner / T10 alerts | MoAlborati (loop) | **Serial merge queue**, in this order (#41 merged; #35 next, then #26) |
  | #28 | T7-real metrics | MoAlborati (loop) | Being fixed |
  | #31 | fix-23 findings | MoAlborati (loop) | Merge steward assigned |
  | #27 | T3 follow-up (384 KiB cap, decode dedupe) | MoAlborati (loop) | Superseded by T3-fix; to be closed |
  | #23 | Orchestrator loop | shrutidoshi94 | Teammate's PR; the loop does not touch it |
- **Open needs-human issues:** #36 (run ONE orchestrator, urgent), #37 (canonical T2 proxy: #14 .mjs vs #21 .js),
  #38 (pitch numbers + "block pure injections" policy), #39 (presenter, 14:30 dry run, fallback video),
  #40 (pre-public check: benchmark exfil targets + teammate local paths). Chat: #32 (start here), #34 (Catherine joining).
- **Last green gate:** `scripts/eval.sh gate` per PR. Delivery gate (≥5 clean replays) pending.
- **Demo rehearsal:** not started (14:30–15:30; fallback video recorded last).

### Schedule (operator, 11:58 PDT)
| Window (PDT) | Work |
|---|---|
| now–13:30 | Land T3 follow-ups + T10 + T9 runner + fixes |
| 13:30–14:30 | Integration, delivery gate (≥5 clean replays), real metrics |
| **14:30** | **FEATURE FREEZE** |
| 14:30–15:30 | Rehearsal; record the fallback video last |
| 15:30–16:00 | Buffer |

### Honest metrics (353-case corpus, T7-real lenses; final numbers after delivery gate)
| System | Detection | Prevention | Benign FP |
|---|---|---|---|
| SentinelProxy T3 | 63.0% | 41.8% | **0%** |
| DVAA baseline | 65.6% | 63.0% | 12.8% |
- T3 catches both cases that evade DVAA's 8 KB scan baseline. DVAA's higher recall comes with 12.8% benign FP.
- In-flight levers: **T3-fix** (supersedes #27), **T3-recall**, **T12 egress** (tool-boundary prevention).

## Backlog pointer
See BACKLOG.md. Next: drain the merge queue (#35, #26), land #28/#31, then T3-fix, T3-recall, T12, then the delivery gate.

## Decision Log (append-only, newest first)
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
  `/home/gingy/crowdstrike-<ticket>`, and the main checkout is orchestrator-only. Cause: an incident where agents shared the main checkout
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
| 1 Exploit+evasion | T1, T6, T6b | #5, #10, #15, #29, #31 | MERGED (#31 open) | Corpus 353 cases; #31 fixes exfil labels |
| 2 Detect+block | T2, T3 | #14, #21, #24, #41, #42; #27 superseded | MERGED core; T3-fix/T3-recall in flight | Request-side block only; canonical proxy = #37 |
| 3 AIDR alert | T4, T10 | #3, #12; #26 | MERGED; T10 in queue | #26 wires verdicts → alerts → dashboard |
| 4 Incident graph | T5 | #11 | MERGED | Real metrics pending delivery gate |
| 5 Scoring | T7, T7-real | #13; #28 | MERGED; #28 being fixed | Detection/prevention split (see Status) |
| 6 Secure contrast | T8, spike | #16, #18, #22 | MERGED | Response-side is alert-only; T12 egress in flight |
| 7 Demo script | T9 | #9; #35 | Draft MERGED; runner in queue | Deck + video at end (#39) |
| Infra | T11, chat | #20, #33 | MERGED | One-command eval + merge gate; chat intake |
