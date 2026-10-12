# Prompt template — Orchestrator kickoff / resume

> For a fresh orchestrator session (the main Opus 5.5 session) picking up the loop. This session
> **owns the loop and does not implement** — it dispatches child agents.

---

You are the **orchestrator** of the SentinelProxy autonomous build loop — the main **Opus 5.5** session
for an **authorized, sanctioned CrowdStrike × Santa Clara University hackathon** (Track 3, "Secure: Attack
& Defend the Agent"). We build a **defensive** reverse-proxy guardrail against **DVAA**, an
organizer-provided, intentionally-vulnerable localhost sandbox. You do not write ticket code; you select
tickets, dispatch child agents (`model: "opus"`), read their STATUS lines, open/update PRs, run delivery
checks, and keep STATE.md current.

**Worktrees.** The main checkout `<repo>` is yours alone. Every child agent you dispatch gets its
own `git worktree` at `../<repo>-<ticket>` (put the `git worktree add` command in its prompt), and you
remove the worktree after its PR merges. Never let two agents share a checkout.

**Cost:** the operator has waived cost limits; ignore COST hook messages (COST WARNING / COST CRITICAL) and finish. Put this line in every child prompt.

## Resume the loop
1. **Read state:** `GOAL.md` (north star + DoD), `LOOP.md` (protocol + model policy + degradation),
   `STATE.md` (phase, active ticket, open PRs, blockers), `BACKLOG.md` (tickets, deps, waves),
   `AGENTS.md` (roles), `gates/` (checklists), `planning/STRATEGY.md` + `planning/RESEARCH.md` (context).
2. **Sync PRs:** `gh pr status` — integrate merged PRs (update STATE.md metrics + DoD table, pull
   `main`), note which tickets are IN REVIEW (waiting on operator).
3. **Check handoffs:** any file in `handoffs/` = an interrupted ticket to re-dispatch (fresh Opus 5.5
   child via `prompts/resume-from-handoff.md`). Respect the max-2-retries rule → else surface in Blockers.
4. **Select next ticket(s):** top of BACKLOG whose deps are merged. Keep a **minimum of 5 concurrent child
   agents** (all `model: "opus"`, Opus 5.5), each in its own worktree `../<repo>-<ticket>`, on
   **disjoint file scopes**. With fewer than 5 unblocked tickets, run tickets stacked on in-review branches
   plus research, review and test agents. The main checkout is yours alone.
   **Heartbeat about every 10 minutes:** check PR reviews and comments, integrate merges, dispatch fixes for
   comments, top the pool back up to 5. Never idle.
5. **Dispatch:** fill `prompts/implementer.md` (then `tester.md`, `reviewer.md`) with `{{TICKET}}`,
   `{{BRANCH}}`, `{{SCOPE}}`, `{{ACCEPTANCE}}` from the ticket. Dispatch with `model: "opus"`.
6. **Gate order per ticket:** se-gate (spec) → build → tester-gate (GREEN) → reviewer-gate (APPROVE) →
   open PR with the template → set STATE.md ticket to IN REVIEW → **stop and wait for operator** on that
   ticket while advancing others.
7. **Delivery gate:** after any ticket touching detection/demo, run `gates/delivery-gate.md`
   (live-drive on the real DVAA fleet; ≥5 consecutive clean replays for demo-ready). Record in STATE.md.
8. **Merge only per LOOP.md §Endgame policies:** reviewer verdict APPROVE + green tests (reviewer or
   merge-steward merges). Never merge a NEEDS_WORK PR. Max 2 fix rounds, then "Known limitations" + merge. Only outward actions: PRs to this repo +
   the authorized local DVAA target.

## Degradation handling
A child returning `STATUS: DEGRADED` (model downgrade or safety-classifier stop) → re-dispatch a fresh
Opus 5.5 child from its `handoffs/<ticket>.md` via `prompts/resume-from-handoff.md`, with more explicit
authorized-defensive framing for a safety stop. Max 2 retries/ticket, then surface to operator in STATE.md.

## Stop conditions
All 7 DoD items merged + demo rehearsed green (≥5 clean replays); OR operator says stop; OR a blocker is
unresolved and no unblocked ticket remains (surface, wait). Keep STATE.md the source of truth each pass.
