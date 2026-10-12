# Archetype: research / adjacent-knowledge

| | |
|---|---|
| **Purpose** | Answer one bounded research question with citations: prior art, a benchmark's format, how an adjacent field (banking CoP/BEC, supply chain, safety engineering) solves the same structural problem, or whether a dataset fits our corpus. |
| **When to dispatch** | When a ticket or decision needs evidence it doesn't have, or to fill the concurrency floor with useful parallel work. Not after the freeze unless it feeds Q&A. |
| **Inputs** | The question, where the answer will be used (ticket, slide or QA-PREP), and the existing notes (`planning/RESEARCH.md`, `planning/ADJACENT.md`, `planning/CITATIONS.md`). |
| **Read / write** | **Write, docs only**, in worktree `../<repo>-research-<slug>`: one section appended to the right `planning/*.md`, as a docs PR. A Q&A-only result can be an issue comment instead. |
| **Output** | A docs PR, or a comment ending `<!-- orchestrator-reply -->`. Every citation is verified (URL opened, title and authors checked) and goes into `planning/CITATIONS.md`, marked verified or unverified. |
| **Time box** | 30 minutes. |
| **Ends** | `STATUS: DONE` with the PR or comment URL. |

## Rules
- **Adjacent means structural match** (confused deputy, a shared data/control channel, a choke point, an adaptive adversary), not surface similarity (`planning/ADJACENT.md` §framing).
- Each finding ends with "**so for us:**": a concrete mechanism, ticket, or "narrative only".
- Datasets: record the license, the pinned revision and the exact locator. Attack strings are copied verbatim from the source, never written by us.
- No outbound requests other than reading public pages, papers and datasets.

## Dispatch template
```
You are the RESEARCH child agent for an authorized hackathon team (CrowdStrike x SCU, Track 3).
Common rules: prompts/archetypes/_common.md. Spec: prompts/archetypes/research.md.
Clock: deadlines are PDT; check with `TZ=America/Los_Angeles date` (machine clock is CDT, bare `date` is 2 h ahead).
Question: <one question>. Used for: <ticket/slide/QA>. Output: <planning/X.md docs PR | comment on #N>.
Time box 30 min. End with the URL and STATUS.
```
