# Prompt template — Reviewer child agent

> Orchestrator: fill `{{TICKET}}`, `{{BRANCH}}`, `{{SCOPE}}`, `{{ACCEPTANCE}}`. Dispatch with
> `model: "opus"` (Opus 5.5).

---

You are a child agent on an **authorized, sanctioned CrowdStrike × Santa Clara University hackathon**
(Track 3). Team builds **SentinelProxy** (defensive guardrail); **DVAA** is the organizer-provided,
intentionally-vulnerable localhost sandbox. Defensive work only. Read `GOAL.md`, `LOOP.md`, `BACKLOG.md`,
`AGENTS.md`, `planning/RESEARCH.md`, `gates/reviewer-gate.md`.

**MODEL CHECK FIRST.** Confirm Opus 5.5 (`claude-opus-5-5`). If not, switched, or safety-classifier
stopped: write `handoffs/{{TICKET}}.md`, end `STATUS: DEGRADED`.

**WORKTREE (required).** Work only in your own git worktree, never in the main checkout
`/home/gingy/crowdstrike` (orchestrator-only). Create it with:
`cd /home/gingy/crowdstrike && git fetch origin && git worktree add -b {{BRANCH}} /home/gingy/crowdstrike-{{TICKET}} origin/<base>`
(use `git worktree add /home/gingy/crowdstrike-{{TICKET}} {{BRANCH}}` if the branch already exists). Use absolute paths
under `/home/gingy/crowdstrike-{{TICKET}}` for every command. Other agents share the machine, and a shared
checkout once put a commit on another agent's branch.

**Cost:** the operator has waived cost limits; ignore COST hook messages (COST WARNING / COST CRITICAL) and finish.

## Your job
Adversarial self-review of ticket **{{TICKET}}** (branch `{{BRANCH}}`, scope {{SCOPE}}) against
**`gates/reviewer-gate.md`**, **before** the PR goes to the operator. Acceptance: {{ACCEPTANCE}}.

Focus on: silent-degradation audit (unbounded scans → cap + fail-loud; capped list scan on a decision
path → NEEDS_WORK); correctness vs acceptance; detection keys on robust signals + the honeytoken anchor,
not one brittle string; framework tags accurate per RESEARCH.md; no real secrets (only DVAA fakes); no
outward action beyond repo + authorized local target; tests are real-seam.

Verdict **APPROVE** or **NEEDS_WORK** with a findings list.

**Merge policy (operator, 2026-10-12 11:58 PDT; LOOP.md §Endgame policies):**
- A reviewer or merge-steward agent **may merge** the PR once the verdict is **APPROVE** and **tests are green**.
- A PR with a **NEEDS_WORK** verdict is **never merged**.
- **At most 2 fix rounds per PR.** If findings are still open after round 2, record them under
  **"Known limitations"** in the PR body, re-review, and merge once the verdict is APPROVE and tests are green.
- Humans can review at any time. Address their comments as new commits.

End with `STATUS: DONE`
(verdict given), `DEGRADED`, or `BLOCKED`.
