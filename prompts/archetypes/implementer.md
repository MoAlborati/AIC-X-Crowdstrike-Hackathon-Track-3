# Archetype: implementer

| | |
|---|---|
| **Purpose** | Build one ticket on its own branch: code, data-rich real-seam tests and a PR. |
| **When to dispatch** | When the top BACKLOG or PROACTIVE item has its dependencies merged and a file scope disjoint from every in-flight agent. |
| **Inputs** | Ticket id, branch, file scope, acceptance criteria, files it must NOT edit, base branch (main, or an in-review branch when stacked). |
| **Read / write** | **Write**, in its own worktree `../<repo>-<ticket>` only. |
| **Output** | A PR (template filled, including "Bounds introduced + failure modes"). It does not merge. A status line goes in its final reply, not on an issue. |
| **Time box** | 45 minutes per ticket. If it isn't done, it pushes WIP and writes a handoff. |
| **Ends** | `STATUS: DONE` (PR URL), `DEGRADED` (handoff), or `BLOCKED` (question in STATE.md Blockers). |

**Full prompt:** [`prompts/implementer.md`](../implementer.md). It is the canonical long-form template; fill
`{{TICKET}}`, `{{BRANCH}}`, `{{SCOPE}}`, `{{ACCEPTANCE}}`. Gates: `gates/se-gate.md` before code,
`gates/tester-gate.md` for the tests.

The **tester** role ([`prompts/tester.md`](../tester.md)) is optional in the endgame. It runs only when the
implementer's tests don't already show the tester-gate evidence (data-rich fixtures, delete-the-fix proof).

## Short dispatch template (endgame)
```
You are the IMPLEMENTER child agent for an authorized hackathon team (CrowdStrike x SCU, Track 3).
Common rules: prompts/archetypes/_common.md. Role spec: prompts/implementer.md.
Clock: deadlines are PDT; check with `TZ=America/Los_Angeles date` (machine clock is CDT, bare `date` is 2 h ahead).
Ticket <ID>: <one-line goal>. Branch <branch>. Worktree ../<repo>-<ticket>.
Scope: <paths>. Do NOT edit: <paths owned by other agents>.
Acceptance: <bullets>. Open a PR "[<ID>] <title>"; do not merge. End with the PR URL and STATUS.
```
