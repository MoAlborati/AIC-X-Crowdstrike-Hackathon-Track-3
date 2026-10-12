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
  the gates' delivery checks, keeps STATE.md current. Merges only under the endgame merge rule below.
- **Implementer** (child agent): builds one ticket on its branch — code + data-rich tests. Runs se-gate.
- **Tester** (child agent): enforces `gates/tester-gate.md` — data-rich fixtures, real seams,
  delete-the-fix proof. GREEN or back to Implementer.
- **Reviewer** (child agent): enforces `gates/reviewer-gate.md` adversarially **before** the PR opens,
  so the operator's review starts clean.
- **Merge-steward** (child agent): merges PRs that meet the endgame merge rule. It has no other authority.

## Chat with the orchestrator (mirror of LOOP.md)
Humans can chat with the orchestrator through GitHub Issues (`CHAT.md`, pinned issue #32, labels `chat` /
`chat-urgent`). It is a priority async intake that runs in parallel with the build loop. The orchestrator answers chat
**before** other work, then resumes the loop. Child agents don't poll chat. The orchestrator relays anything they need.

## Endgame policies (mirror of LOOP.md §Endgame policies; operator, 2026-10-12 11:58 PDT)
Operator's direction: "limit scope, our goal is to win the hackathon".
- **Deadline 16:00 PDT. Feature freeze 14:30 PDT.** Delivery gate (≥5 clean replays) and real metrics run 13:30–14:30.
  Rehearsal runs 14:30–15:30, with the fallback video recorded last. 15:30–16:00 is buffer.
- **Merge rule:** a reviewer or merge-steward agent may merge once the reviewer verdict is **APPROVE** and the **tests are green**. Never merge a NEEDS_WORK PR.
  Humans can review at any time.
- **Max 2 fix rounds per PR.** Anything still open after that goes under "Known limitations" in the PR, then merge.
- **T3 frozen minimum:** honeytoken tripwire, destination provenance, full-payload fail-closed request-side scan, and T4 verdicts.
  Everything else is stretch.
- **Prevention boundary:** DVAA executes tools in-process, so the proxy blocks only request-side (pre-forward) attacks.
  Response-side checks are **alert-only**. The pitch claim waits for the egress spike.
- **Repo goes public:** judges get access now, and the public release comes later. No secrets or private notes in commits.

## Worktree rule (mirror of LOOP.md §Worktrees)
One worktree per ticket, sibling of the main checkout (`<repo>` = the main checkout's absolute path).
- Each concurrently running ticket **MUST** use its own `git worktree` at `../<repo>-<ticket>`.
  Child agents work, commit and push only in their worktree.
- The main checkout `<repo>` is **orchestrator-only**.
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
