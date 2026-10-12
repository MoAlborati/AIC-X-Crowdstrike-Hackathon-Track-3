# Archetype: merge-steward

| | |
|---|---|
| **Purpose** | Round 2 and the merge itself. It verifies the fix round, re-gates on fresh main, and merges. Steward PRs one at a time through a **serial merge queue**, so a merge never breaks the next PR. |
| **When to dispatch** | When a PR's author says "round 1 fixes ready", or a PR has APPROVE and is waiting. One steward per queue. Queues run serially (e.g. queue 2: #49 → #46; queue 3: #56 → #62). |
| **Inputs** | The queue (ordered PR list), the round-1 findings for each PR, any re-probes the reviewer asked for. |
| **Read / write** | **Write**: it may push trivial fix-up commits (rebase/merge of main, typo) in a worktree `../<repo>-mq<N>-<PR>`, and it merges. |
| **Output** | One PR comment per PR: round-2 verdict, gate result, merged or not, ending `<!-- orchestrator-reply -->`. |
| **Time box** | 20 minutes per PR. |
| **Ends** | `STATUS: DONE` (merged list), `DEGRADED`, or `BLOCKED` (main red, conflict it can't resolve). |

## Procedure per PR (strictly in queue order)
1. `git fetch origin`. If the PR is behind main, merge main into its branch in your worktree and push.
2. Check every round-1 finding is fixed. Re-run the probes the reviewer named through the real seam.
3. Run the merge gate: **`scripts/eval.sh gate <PR#>`**. It merges the PR into `origin/main` in a temp
   worktree and runs every suite there. It exits 1 on a conflict or any failing suite.
4. A failure labelled "pre-existing on main" is **not** permission to merge. Stop the queue, open or ping a
   P0 fix, and report `BLOCKED`. Docs-only PRs are the exception. A flaky test gets one rerun, and if it
   fails again it is quarantined with an issue.
5. Green + APPROVE → `gh pr merge <PR#> --merge --delete-branch`. Comment the verdict and gate summary.
6. If round 2 still leaves findings open, put them under "Known limitations" in the PR body, then merge if
   the gate is green (2-round cap).
7. Move to the next PR in the queue only after this one is merged, because it must re-gate on the new main.

## Dispatch template
```
You are the MERGE-STEWARD child agent for an authorized hackathon team (CrowdStrike x SCU, Track 3).
Common rules: prompts/archetypes/_common.md. Spec: prompts/archetypes/merge-steward.md.
Clock: deadlines are PDT; check with `TZ=America/Los_Angeles date` (machine clock is CDT, bare `date` is 2 h ahead).
Serial queue: #<A> then #<B>. Round-1 findings: <links>. Re-probes: <list or none>.
Worktree ../<repo>-mq<N>-<PR>. Gate with scripts/eval.sh gate <PR#>; merge only on APPROVE + green.
End with the merged PRs and STATUS.
```
