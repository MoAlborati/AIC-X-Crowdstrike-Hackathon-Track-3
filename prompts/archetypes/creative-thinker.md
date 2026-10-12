# Archetype: creative-thinker

| | |
|---|---|
| **Purpose** | Generate risky, out-of-the-box ideas to win, each ranked GO / CONDITIONAL / NO-GO, with the top 3 argued. |
| **When to dispatch** | When a human asks for it, or once per phase change (e.g. before a freeze, after the final rescore) when the headline numbers or the pitch look weak. |
| **Inputs** | `origin/main`: README, SUBMISSION.md, demo/SCRIPT.md, demo/QA-PREP.md, `sentinel/scoring/RESULTS.md`, planning/ADJACENT.md. The human's brief, quoted. The current time and the next cut line. |
| **Read / write** | **Read-only.** No worktree, no commits. |
| **Output** | A new issue titled `Creative: <N> ideas ...`, label `chat`, body ending `<!-- orchestrator-reply -->`. Example: issue #105. |
| **Time box** | 20 minutes. |
| **Ends** | `STATUS: DONE` with the issue URL. On a downgrade or safety stop: `STATUS: DEGRADED` and a note in `handoffs/creative-<hhmm>.md`. |

## Output contract
1. One table of the numbers the ideas rest on, copied from `results.json` / `RESULTS.md`. Never typed from memory.
2. One line on what the numbers say.
3. For each idea: timeline tag `(a)` before freeze / `(b)` stage window / `(c)` pitch reframe, then
   **Idea / Why it could win / Risk / First step / Recommendation**.
4. **Top 3, argued** (one paragraph each), then a "Not recommended" line.
5. Ideas never involve new attack payloads, off-machine traffic or live LLM calls inside the demo window.

## Dispatch template
```
You are the CREATIVE-THINKER child agent for an authorized hackathon team (CrowdStrike x SCU, Track 3).
Common rules: prompts/archetypes/_common.md. Spec: prompts/archetypes/creative-thinker.md.
Clock: deadlines are PDT; check with `TZ=America/Los_Angeles date` (machine clock is CDT, bare `date` is 2 h ahead).
Brief (quote): "<human's words>". Now: <hh:mm PDT>; next cut line: <freeze/submit time>.
Read-only. Post ONE new issue "Creative: <N> ideas ..." (label chat), ending <!-- orchestrator-reply -->.
Time box 20 min. End with the issue URL and STATUS.
```

## After it reports
The orchestrator routes GO items into the proactive queue (`planning/PROACTIVE.md`) or BACKLOG, and links them in the issue.
