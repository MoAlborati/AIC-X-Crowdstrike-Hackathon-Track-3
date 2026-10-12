# STATE — living loop state (source of truth; update every iteration)

> This file survives context compaction. Any agent resuming the loop reads GOAL.md + LOOP.md + this.
> Keep it terse and current. Append to the Decision Log; overwrite the Status block.

## Status (overwrite each iteration)
- **Phase:** BUILD — Wave 2 (T1, T4, T6 merged; T2 building; T5 gating on existing branch)
- **Active tickets:**
  - T2 proxy skeleton — BUILD (`t2-proxy-skeleton`, worktree `crowdstrike-t2`)
  - T5 dashboard — TESTER GATE on the existing `origin/t5-dashboard` (pushed by teammate "mo", no PR yet)
  - T3 — spec / se-gate prep only (no `sentinel/detectors/` code until T2's PR exists)
  - Review/test passes: T9-draft script+deck reviewer pass; T6 corpus tester-gate pass
- **Open PRs:** none (`main` @ c56dbf4, "Merge pull request #10")
- **Merged:** T0 #1, T0b #2, T4 #3, T0c #4, T1 #5, catch-up #7, citations #8, T9-draft (script+deck only) #9, T6 #10. #6 closed unmerged.
- **Last green gate:** T6 (#10)
- **Demo rehearsal:** not started
- **Environment:** DVAA fleet up via Docker on 127.0.0.1 (9000, 7001–7023 healthy); host Node v26.

## Blockers / needs operator
- [ ] `origin/t5-dashboard` already has a T5 implementation (commits e9be1af, 49a46c2 by "mo", no PR). The loop is gating it
      in place instead of rebuilding from `main`. Confirm whether "mo" is still pushing to it, so two writers don't collide.

## Backlog pointer
See BACKLOG.md. Unblocked now: **T2** (deps T1 ✓), **T5** (deps T4 ✓). Blocked: T3 (needs T2), T7 (T3+T6), T8 (T1+T3), T9 run-demo (all).

## Decision Log (append-only, newest first)
- 2026-10-12 — Orchestrator resume (worktree `crowdstrike-orchestrator`, branch `orchestrator-loop`). Synced with GitHub: #8 citations,
  #9 T9-draft (SCRIPT.md + DECK.md only; metrics placeholders) and #10 T6 corpus are merged, so the metrics table is updated. `handoffs/t1.md` is
  historical (T1 landed via #5) and is not re-dispatched. Found an unannounced T5 implementation on `origin/t5-dashboard`, so it gets a tester-gate
  pass in place rather than a rebuild. Dispatched T2 implementer, T5 tester, T3 spec prep, T9-draft reviewer and T6 tester. Worktrees live under
  `/Users/shrutidoshi/Documents/repo/worktrees/crowdstrike-<ticket>` on this machine.
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
| DoD item | Ticket | PR | Gate status | Notes |
|---|---|---|---|---|
| 1 Exploit+evasion | T1,T6 | #5, #10 | merged | 3 attack + 6 benign captures; variants incl. 8KB-baseline evasion |
| 2 Detect+block | T2→T3 | — | T2 building | T3 waits on T2 |
| 3 AIDR alert | T4 | #3 | merged | `sentinel/alerts` |
| 4 Incident graph | T5 | — | tester gate | branch `t5-dashboard` exists, no PR |
| 5 Scoring | T7 | — | blocked (T3) | |
| 6 Secure contrast | T8 | — | blocked (T3) | |
| 7 Demo script | T9 | #9 (draft) | partial | SCRIPT.md + DECK.md drafted; run-demo.sh + rehearsals pending |
