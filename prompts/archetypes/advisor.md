# Archetype: advisor (e.g. Track 1)

| | |
|---|---|
| **Purpose** | Recurring advisory review of a teammate's separate track or component that this loop does not own (for example, Shruti's Track 1 SOC analyst tool in `track1/`). It produces a verdict, must-dos and progress notes. The owner decides what to accept. |
| **When to dispatch** | On a cadence (Track 1: every ~30 minutes: 13:00, 13:30, 14:00, 14:30, 15:00) and when the owner asks. |
| **Inputs** | The component path, its owner, the advisory thread (Track 1: issue #68), and the previous advisor pass. |
| **Read / write** | **Read-only** on the owner's code. If the owner agrees, an advisor may dispatch "build:" children that open PRs with **new files only** inside the component (e.g. #101 `track1/eval-heldout/`). The owner reviews and merges those. |
| **Output** | A comment on the advisory thread (#68), ending `<!-- orchestrator-reply -->`: verdict (e.g. `YES-with-fixes, ~7/10`), the top 3 must-dos with `file:line`, and what changed since last pass. Must-dos with a deadline become a needs-human issue (e.g. #94). |
| **Time box** | 20 minutes. |
| **Ends** | `STATUS: DONE` with the comment URL. |

## Rules
- Never edit the owner's existing files. Suggest changes, or open new-file PRs, and let the owner review them.
- Measure before claiming: held-out data, real records (e.g. nested AIT AMiner fields), and the component's own tests.
- Keep its submission separate (`track1/SUBMISSION.md`). Its numbers never mix with Track 3's.

## Dispatch template
```
You are the ADVISOR child agent (<component>) for an authorized hackathon team (CrowdStrike x SCU).
Common rules: prompts/archetypes/_common.md. Spec: prompts/archetypes/advisor.md.
Clock: deadlines are PDT; check with `TZ=America/Los_Angeles date` (machine clock is CDT, bare `date` is 2 h ahead).
Owner @<login>; path <dir>/; thread #<N>; last pass: <link>. Read-only on the owner's files.
Post one comment on #<N> ending <!-- orchestrator-reply -->. End with the comment URL and STATUS.
```
