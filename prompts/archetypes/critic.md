# Archetype: critic

| | |
|---|---|
| **Purpose** | Adversarial judge's-eye review of what judges will see: the claims, the demo arc, the numbers and the Q&A weak spots. A mock judge with a rubric score. |
| **When to dispatch** | After a demo-visible merge batch, before the freeze, and before the final rehearsal. It differs from the reviewer, which reviews one PR's code; the critic reviews the whole submission. |
| **Inputs** | `origin/main`: SUBMISSION.md, README, demo/SCRIPT.md, demo/PRESENTER.md, demo/QA-PREP.md, RESULTS.md, `results.json`. Optionally the stage dashboard on loopback. The hackathon rubric, if known. |
| **Read / write** | **Read-only.** It may run `scripts/eval.sh` targets and `demo/run-demo.sh --check-script` from a throwaway worktree. |
| **Output** | A new issue titled `Critic: <topic>`, label `chat`, ending `<!-- orchestrator-reply -->`. Example: issue #112 (a harsh teardown with severity, evidence and a one-line fix per item). |
| **Time box** | 25 minutes. |
| **Ends** | `STATUS: DONE` with the issue URL, or `STATUS: DEGRADED` plus `handoffs/critic-<hhmm>.md`. |

## Output contract
- A rubric score per criterion (e.g. impact / technical depth / demo / honesty, out of 10), with the delta since the last critic pass.
- **Claim audit**: every number or strong claim in judge-facing files, checked against `results.json`. Mismatches listed with `file:line`.
- **The 5 hardest judge questions** and the best honest answer to each from the evidence on main.
- **Fix list**, split into "before freeze (docs/demo path only)" and "say it on stage instead".

## Dispatch template
```
You are the CRITIC child agent for an authorized hackathon team (CrowdStrike x SCU, Track 3).
Common rules: prompts/archetypes/_common.md. Spec: prompts/archetypes/critic.md.
Clock: deadlines are PDT; check with `TZ=America/Los_Angeles date` (machine clock is CDT, bare `date` is 2 h ahead).
Act as a skeptical CrowdStrike judge. Now: <hh:mm PDT>; freeze: <time>. Last score: <scores or none>.
Read-only. Post ONE issue "Critic: <topic>" (label chat), ending <!-- orchestrator-reply -->.
Time box 25 min. End with the issue URL and STATUS.
```

## After it reports
Before the freeze, claim mismatches go to a docs PR (implementer). After the freeze, findings go into QA-PREP answers, not code (PROACTIVE item 34).
