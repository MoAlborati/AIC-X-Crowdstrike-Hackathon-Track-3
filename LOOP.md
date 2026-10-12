# LOOP — Autonomous Goal-Loop Protocol

How we execute GOAL.md autonomously through agents, shipping PRs you review/respond to.
Modeled on the firm's convergence process (see `gates/` — encodes the content-engine data-scale rules).

## Roles
- **Operator (you, humans):** review PRs, approve/merge, answer blockers in STATE.md. Final authority.
- **Orchestrator (lead Claude session):** owns the loop. Picks tickets, dispatches agents, opens PRs,
  updates STATE.md, enforces gates. Merges only under §Endgame policies (reviewer APPROVE + green tests).
- **Implementer agent:** builds one ticket on a feature branch. Writes code + tests.
- **Tester agent:** enforces `gates/tester-gate.md` (data-rich fixtures, real seams, delete-the-fix proof).
- **Reviewer agent:** enforces `gates/reviewer-gate.md` (adversarial self-review) BEFORE the PR opens,
  so the human review starts from a clean baseline.
- **Merge-steward agent:** merges PRs that meet the §Endgame policies merge rule. It has no other authority.
- **Every child agent** ends its final reply with one status line: `STATUS: DONE | DEGRADED | BLOCKED`
  (see Model policy below).

## Model policy
- **Orchestrator = the main Opus 5.5 session. It does not implement.** It selects tickets, fills prompt
  templates (`prompts/`), dispatches child agents, reads their STATUS lines, opens/updates PRs and
  keeps STATE.md current.
- **All work is done by child agents dispatched with `model: "opus"` (Opus 5.5)**: implementer,
  tester and reviewer alike. No other model tiers for ticket work.
- **Status contract:** every child ends its final reply with exactly one line:
  `STATUS: DONE | DEGRADED | BLOCKED` (DONE = ticket scope complete + PR opened or gate verdict given;
  DEGRADED = model check failed, handoff written; BLOCKED = needs operator/orchestrator input, reason
  stated on the lines above).

### Degradation protocol
Child agents may be silently downgraded to a weaker model on security topics (this project is
defensive, but the subject matter is prompt injection + exfiltration).
1. Every child checks its own model at start and keeps an eye out mid-task. If it is **not Opus 5.5**
   (or notices it was switched mid-task), it stops new work immediately and wraps up:
   - commit WIP to its ticket branch (trailer as below) and push;
   - write `handoffs/<ticket>.md` with: **done / in-progress / next steps / branch + last commit /
     open questions**;
   - end with `STATUS: DEGRADED`.
2. The orchestrator then re-dispatches a **fresh Opus 5.5 child** using `prompts/resume-from-handoff.md`
   pointed at that handoff file.
3. **Safety-classifier stop:** a child stopped by a safety classifier follows the same handoff path;
   the orchestrator re-dispatches with more explicit authorized-defensive framing (sanctioned hackathon,
   organizer-provided intentionally-vulnerable DVAA sandbox on localhost, goal = detector/guardrail).
4. **Max 2 retries per ticket.** After the second failed retry, the orchestrator stops dispatching that
   ticket and surfaces it to the operator in STATE.md **Blockers** (with the handoff path).

## Chat with the orchestrator (priority async intake)
Humans can reach the orchestrator through GitHub Issues at any time (see `CHAT.md`). `scripts/chat-poll.sh`
emits a `CHAT_EVENT` for each unanswered message in any open issue. Chat runs **in parallel** with the build
loop, and the orchestrator **answers chat before other work**, with `chat-urgent` first. Every reply carries
`<!-- orchestrator-reply -->`. Work requests from chat enter the loop as tickets or child agents, subject to
§Endgame policies.

## Remote & branching
- Remote: `origin` = https://github.com/shrutidoshi94/AIC-X-Crowdstrike-Hackathon (we have WRITE).
- Base branch: `main`. One branch per ticket: `tN-short-slug` (e.g. `t3-detector-core`).
- One PR per ticket. PR title: `[T3] Detector core: honeytoken + taint + egress`. Small, reviewable.

## Iteration lifecycle (one pass)
1. **Select:** Orchestrator reads STATE.md + BACKLOG.md, picks the top ticket whose deps are merged.
   Independent tickets may run in parallel (separate agents, separate branches).
2. **SE gate:** confirm the ticket's spec + acceptance criteria + bounds are explicit
   (`gates/se-gate.md`). If unclear, ask the operator in STATE.md Blockers; do not guess.
3. **Build:** Implementer agent creates the branch, implements, writes tests with data-rich fixtures.
4. **Tester gate:** Tester agent runs `gates/tester-gate.md`. Must be GREEN (real seams, >=200-equiv
   fixtures where applicable, delete-the-fix proof for any bug fix). RED -> back to Build.
5. **Reviewer gate:** Reviewer agent runs `gates/reviewer-gate.md` adversarially. Fix findings.
6. **Open PR:** push branch, open PR with the template filled (links ticket, DoD item, gate evidence).
   Set STATE.md: ticket -> IN REVIEW, record PR number. **STOP and wait for operator** on that ticket.
7. **Review + merge:** a reviewer or merge-steward agent merges once the reviewer verdict is APPROVE and
   tests are green (§Endgame policies). At most 2 fix rounds per PR. Humans may review at any time; their
   comments are addressed as new commits (never force-push or force-merge).
8. **Integrate:** after merge, update STATE.md metrics table, mark DoD item, pull main, pick next ticket.
9. **Delivery gate (recurring):** after any ticket touching detection/demo, run `gates/delivery-gate.md`
   — a live-drive on the data-rich DVAA target (not a toy fixture). Record result in STATE.md.

## Endgame policies (operator, 2026-10-12 11:58 PDT)
Operator's direction: "limit scope, our goal is to win the hackathon". These override any earlier rule in this file that conflicts with them.
- **Deadline: 16:00 PDT.** Schedule:
  - now–13:30: land T3 at its minimum scope, plus #14 (T2), T10, and fixes
  - 13:30–14:30: integration, delivery gate (**≥5 clean replays**), real metrics
  - **14:30: FEATURE FREEZE.** After this, only fixes to the demo path, with no new features
  - 14:30–15:30: rehearsal. **The fallback video is recorded last**
  - 15:30–16:00: buffer
- **Merge authority:** a reviewer or merge-steward agent may merge a PR once (a) its reviewer verdict is
  **APPROVE** and (b) its **tests are green**. A NEEDS_WORK PR is never merged. Humans can review at any time. Docs-only PRs may be merged by
  their author after a conflict check.
- **Review-round cap:** at most **2 fix rounds per PR**. Anything still open after round 2 goes in the PR
  body under **"Known limitations"**, and the PR then merges.
- **T3 scope frozen** to the demo-critical minimum:
  1. honeytoken tripwire
  2. destination provenance
  3. full-payload, fail-closed, request-side scan
  4. T4 verdicts

  Everything else in T3 is **stretch**: do not start it before the freeze, and do not start it after.
- **Architecture finding (T8):** DVAA agents execute tools **in-process**, so the proxy can **prevent only
  request-side (pre-forward)** attacks. **Response-side checks are alert-only.** Do not claim response-side
  blocking anywhere. The pitch claim is decided after the egress spike.
- **Repo visibility:** judges will get access, and the repo goes **public** later. Keep commits free of secrets
  and private notes (honeytokens are DVAA's fake planted values only). Presentation materials and the video
  come at the end.

## Worktrees (required for concurrent tickets)
- **Every concurrently running ticket MUST use its own `git worktree`** at `/home/gingy/crowdstrike-<ticket>`
  (e.g. `/home/gingy/crowdstrike-t3`), created with
  `git worktree add -b <branch> /home/gingy/crowdstrike-<ticket> origin/<base>`. Agents work, commit and push only there.
- **The main checkout (`/home/gingy/crowdstrike`) is orchestrator-only.** No child agent edits, checks out a branch or
  commits in it.
- Why: during T0b/T1, agents shared the main checkout, and one agent's `git checkout` moved HEAD under another, so a commit landed on
  **another agent's branch**. Separate worktrees give each agent its own HEAD and index.
- The orchestrator removes a ticket's worktree (`git worktree remove`) after its PR merges or is abandoned.

## Parallelism rule
**Minimum 5 concurrent child agents, each in its own worktree with disjoint file scope** (operator directive,
replaces the earlier "at most 3 implementer agents" cap). Every child runs on the highest model (Opus 5.5,
`model: "opus"`). When fewer than 5 tickets are unblocked, the orchestrator fills the remaining slots with
**tickets stacked on in-review branches** (branch from the in-review PR's head; the PR targets that branch),
plus **research, review and test agents**. Never two agents on the same files (avoids merge conflicts), and never two agents in the
same checkout (§Worktrees). Dashboard + detector + attack bench are disjoint and parallel-safe early on.

## How the loop keeps running (autonomy mechanism)
- **The orchestrator is always working.** A ticket in review never idles the loop: the orchestrator keeps
  ≥5 child agents running (§Parallelism), using stacked tickets, research, review and test agents when
  unblocked tickets run out.
- **Heartbeat about every 10 minutes:** check open PRs for reviews and comments (`gh pr status`, `gh pr view
  --comments`), integrate merged ones, dispatch agents to address review comments as new commits, top the pool back up to ≥5,
  and update STATE.md.
- Hard stop conditions: **16:00 PDT deadline**; OR all 7 DoD items merged + demo rehearsed green; OR operator says stop; OR a
  blocker in STATE.md is unresolved and no unblocked ticket remains (then: surface, wait).

## Guardrails (firm rules, non-negotiable)
- **Bounded + fail-loud:** any input the detector assembles/scans must be bounded; on overflow, ALERT/
  raise — never silently truncate. (DVAA's 8KB-scan baseline is the anti-pattern we beat.)
- **Data-rich verification:** gates require real DVAA agents / data-rich fixtures, not 2-3 row toys.
- **No silent degradation:** no feature ships behind a mock of the thing it's supposed to test.
- **Outward actions:** only PRs to this repo + the authorized DVAA target. Nothing else external.
- **No secret leakage** in commits/PRs (the honeytokens are DVAA's fake planted secrets only).

## Commit/PR attribution
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
- PR body trailer: `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
