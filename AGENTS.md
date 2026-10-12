# AGENTS — roles, model policy, status contract, handoffs

How the agents in this autonomous loop relate. Read with `GOAL.md`, `LOOP.md`, `STATE.md`, `BACKLOG.md`.
This is an **authorized, sanctioned CrowdStrike × Santa Clara University hackathon** (Track 3, "Secure:
Attack & Defend the Agent"). We build a **defensive** detector/guardrail (SentinelProxy) against DVAA, an
**organizer-provided, intentionally-vulnerable training sandbox** running on localhost. All work is
defensive and scoped to this repo + the authorized local DVAA target.

## Roles
- **Operator** (humans): final authority. Reviews PRs, approves/merges, answers Blockers in STATE.md.
- **Orchestrator** (the main Opus 5.5 session): owns the loop; **does not implement**. Selects tickets,
  fills `prompts/` templates, dispatches child agents, reads their STATUS lines, opens/updates PRs, runs
  the gates' delivery checks, keeps STATE.md current. Never merges its own PR without operator approval.
- **Implementer** (child agent): builds one ticket on its branch — code + data-rich tests. Runs se-gate.
- **Tester** (child agent): enforces `gates/tester-gate.md` — data-rich fixtures, real seams,
  delete-the-fix proof. GREEN or back to Implementer.
- **Reviewer** (child agent): enforces `gates/reviewer-gate.md` adversarially **before** the PR opens,
  so the operator's review starts clean.

## Worktree rule (mirror of LOOP.md §Worktrees)
- Each concurrently running ticket **MUST** use its own `git worktree` at `/home/gingy/crowdstrike-<ticket>`.
  Child agents work, commit and push only in their worktree.
- The main checkout `/home/gingy/crowdstrike` is **orchestrator-only**.
- Reason: a commit landed on another agent's branch when agents shared one checkout.

## Concurrency (mirror of LOOP.md §Parallelism)
- **Minimum 5 concurrent child agents** at all times, each on Opus 5.5, each in its own worktree with a
  disjoint file scope. With fewer than 5 unblocked tickets, run tickets stacked on in-review branches plus
  research, review and test agents.
- The orchestrator is always working and runs a heartbeat about every 10 minutes that checks PR reviews and comments.

## Cost hooks
The operator has waived cost limits. Child agents ignore COST WARNING/CRITICAL hook messages and finish the task.

## Model policy (mirror of LOOP.md §Model policy)
- Orchestrator = main **Opus 5.5** session, non-implementing.
- All ticket work is done by child agents dispatched with **`model: "opus"` (Opus 5.5)**. No other tier.
- Rationale: this is security subject matter; a weaker model degrades detection quality and may be
  silently substituted.

## Degradation protocol
Child agents may be silently downgraded on security topics, or stopped by a safety classifier.
1. **Model check:** each child verifies it is Opus 5.5 at start and watches for a mid-task switch.
2. **If not Opus 5.5 (or switched):** stop new work → commit WIP to the ticket branch + push →
   write `handoffs/<ticket>.md` → end with `STATUS: DEGRADED`.
3. **If stopped by a safety classifier:** same handoff path; the orchestrator re-dispatches with more
   explicit authorized-defensive framing (sanctioned hackathon, organizer-provided local DVAA sandbox,
   goal = detector/guardrail).
4. Orchestrator re-dispatches a **fresh Opus 5.5 child** via `prompts/resume-from-handoff.md`.
5. **Max 2 retries per ticket**, then surface to the operator in STATE.md **Blockers** with the handoff path.

## Status line contract
Every child's final reply ends with exactly one line:
- `STATUS: DONE` — ticket scope complete; PR opened (implementer) or gate verdict given (tester/reviewer).
- `STATUS: DEGRADED` — model check failed or safety-classifier stop; WIP committed, `handoffs/<ticket>.md`
  written. Preceding lines: what remains.
- `STATUS: BLOCKED` — needs operator/orchestrator input; the reason + what's needed stated above the line.

## How `handoffs/` works
- One file per interrupted ticket: `handoffs/<ticket>.md` (e.g. `handoffs/T3.md`).
- Required sections: **Done** / **In progress** / **Next steps** / **Branch + last commit** / **Open questions**.
- The orchestrator reads it and dispatches a fresh Opus 5.5 child with `prompts/resume-from-handoff.md`
  pointed at the file. The resuming child deletes or supersedes the handoff when the ticket reaches DONE.
- `handoffs/.gitkeep` keeps the directory in git while empty.
