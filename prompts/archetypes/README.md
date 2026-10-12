# Agent archetypes: index

These are reusable child-agent roles for this project's orchestrator loop. Every archetype file has the same
fields: **purpose, when to dispatch, inputs, read/write, output contract, time box, how it ends**, plus a
**short dispatch template**. Templates stay short on purpose, because long inline security prompts can trip
the safety classifier. The shared rules (framing, **CLOCK**, model check, worktree, cost, Fact-Forcing Gate,
security, posting marker, merging, STATUS) live once in [`_common.md`](_common.md).

Cold start or post-compaction: read [`../../RESUME.md`](../../RESUME.md) first.

| Archetype | File | R/W | Posts to | Time box | Example output |
|---|---|---|---|---|---|
| Implementer | [`implementer.md`](implementer.md) → long form [`../implementer.md`](../implementer.md) | write (own worktree) | PR | 45 m | most PRs |
| Tester (optional in endgame) | long form [`../tester.md`](../tester.md) | write (tests only) | final reply | 30 m | |
| Reviewer (round 1) | [`reviewer.md`](reviewer.md) → long form [`../reviewer.md`](../reviewer.md) | read + PR comment | PR comment | 20 m | |
| Merge-steward (round 2, serial queue) | [`merge-steward.md`](merge-steward.md) | write + merge | PR comment | 20 m / PR | queues 2 and 3 (#49 → #46, #56 → #62) |
| Integration-check | [`integration-check.md`](integration-check.md) | read (throwaway merge) | issue comment | 20 m | |
| Delivery-gate | [`delivery-gate.md`](delivery-gate.md) | runs gate; REHEARSAL entry | issue comment | 30 m | #85, #96 |
| Final-rescore / endgame-submit | [`final-rescore.md`](final-rescore.md) | write, self-merge on green | PR + #38 / #106 | 25 m | #108 |
| Chat-responder | [`chat-responder.md`](chat-responder.md) | read + comment | issue comment | 1 m ack / 15 m | #32 |
| Advisor (e.g. Track 1) | [`advisor.md`](advisor.md) | read; new-file PRs if owner agrees | advisory thread | 20 m | #68, #94, #101 |
| Research / adjacent-knowledge | [`research.md`](research.md) | docs PR | PR or comment | 30 m | `planning/ADJACENT.md` |
| Creative-thinker | [`creative-thinker.md`](creative-thinker.md) | read-only | new issue | 20 m | #105 |
| Project-overseer | [`project-overseer.md`](project-overseer.md) | read-only | new issue | 25 m | #110 |
| Critic | [`critic.md`](critic.md) | read-only | new issue | 25 m | #112 |
| Competitive-reviewer (standing, fans out workers) | [`competitive-reviewer.md`](competitive-reviewer.md) | read-only toward other repos; workers write PRs | #140 comment | 30 m / pass | #140 |
| Custodian (cleanup + escalation) | [`custodian.md`](custodian.md) | removes merged worktrees, orphan PIDs/stacks; closes answered issues | new issue | 25 m | `Custodian: cleanup log + escalations` |
| Resume a degraded child | long form [`../resume-from-handoff.md`](../resume-from-handoff.md) | as original role | as original | as original | `handoffs/` |
| Orchestrator (not a child) | [`../orchestrator-kickoff.md`](../orchestrator-kickoff.md) + [`../../RESUME.md`](../../RESUME.md) | | | | |

## How to dispatch
1. Copy the archetype's dispatch template and fill the `<…>` slots. Get the time from `TZ=America/Los_Angeles date`.
2. Dispatch with the Agent tool, `model: "opus"` (Opus 5.5). Never a lower tier.
3. Record the dispatch in `planning/PROACTIVE.md` (`[TAKEN HH:MM]`) and the worktree in your notes.
4. Read the child's final `STATUS:` line. On `DEGRADED`, re-dispatch from its `handoffs/<ticket>.md` with
   `../resume-from-handoff.md` (at most 2 retries, then STATE.md Blockers).

## Merge flow
implementer (PR) → reviewer (round 1: APPROVE / NEEDS_WORK) → implementer fixes → merge-steward (round 2,
serial queue, `scripts/eval.sh gate <PR#>`, merge) → delivery-gate after demo-touching merges.
Docs-only PRs: the author runs `scripts/eval.sh gate <PR#>` and self-merges on green.
