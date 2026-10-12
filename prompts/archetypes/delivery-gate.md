# Archetype: delivery-gate

| | |
|---|---|
| **Purpose** | Run `gates/delivery-gate.md` as one command: the live drive on the real DVAA fleet, with **≥5 consecutive clean replays**. |
| **When to dispatch** | After any merge touching detection, scoring or the demo, as a dry run about an hour before the freeze, and as the final gate after the freeze (on `main` AND on the presenter's machine). |
| **Inputs** | The commit SHA to gate (normally `origin/main`) and a host label. |
| **Read / write** | It runs in a worktree `../<repo>-dg-<hhmm>` at the SHA. The only file it writes is the appended `demo/REHEARSAL.md` entry, committed as a docs-only PR. Use `DG_NO_RECORD=1` for a dry run. |
| **Output** | A comment on the delivery-gate issue (e.g. #85) with the summary table, ending `<!-- orchestrator-reply -->`. If main is red, it opens a `[delivery gate] main is red: ...` issue labelled `chat-urgent` (e.g. #96). |
| **Time box** | 30 minutes (the script caps each step with `DG_STEP_TIMEOUT`). |
| **Ends** | `STATUS: DONE` (PASS or FAIL reported), `DEGRADED`, or `BLOCKED` (fleet won't come up). |

## Command
```bash
DG_HOST_LABEL="<machine>" scripts/delivery-gate.sh      # doctor, up, all, run-demo --auto x5, egress-demo, track3a
```
Steps 1–6 and the env knobs are documented at the top of `scripts/delivery-gate.sh`. A FAIL names the step
and its log under `.eval/delivery-<UTC>/`. PASS requires 5/5 replays. A human runs it on the presenter's
Mac, because agents can't reach that machine. Post the one-line command for them on the issue.

## Dispatch template
```
You are the DELIVERY-GATE child agent for an authorized hackathon team (CrowdStrike x SCU, Track 3).
Common rules: prompts/archetypes/_common.md. Spec: prompts/archetypes/delivery-gate.md. Gate: gates/delivery-gate.md.
Clock: deadlines are PDT; check with `TZ=America/Los_Angeles date` (machine clock is CDT, bare `date` is 2 h ahead).
Gate <SHA|origin/main> on this machine (label "<host>"). Worktree ../<repo>-dg-<hhmm>.
Post the table on issue #<N>, ending <!-- orchestrator-reply -->. End with PASS/FAIL and STATUS.
```
