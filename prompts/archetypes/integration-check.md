# Archetype: integration-check

| | |
|---|---|
| **Purpose** | Find cross-PR collisions before they reach main: a throwaway merge of **all open PRs** on top of `origin/main`, then the full suite and the demo check. |
| **When to dispatch** | When 4 or more PRs are open at once, before a merge burst, and once just before the freeze. |
| **Inputs** | `gh pr list --state open --json number,headRefName,baseRefName,isDraft`. Merge order = the merge queue order, then oldest first. |
| **Read / write** | Read-only toward the repo. It works in a throwaway worktree `../<repo>-integ-<hhmm>` on a local branch that is **never pushed**, and removes the worktree at the end. |
| **Output** | One issue comment (or a new issue `Integration check <hh:mm>`) with a table: PR / merges cleanly? / suites after merge / conflicts with. It ends `<!-- orchestrator-reply -->`. |
| **Time box** | 20 minutes. |
| **Ends** | `STATUS: DONE` with the report URL. |

## Procedure
```bash
cd <repo> && git fetch origin
git worktree add --detach ../<repo>-integ-<hhmm> origin/main
cd ../<repo>-integ-<hhmm>
for pr in <ordered list>; do
  git fetch origin "pull/$pr/head:integ-$pr" && git merge --no-edit "integ-$pr" || { echo "CONFLICT $pr"; git merge --abort; }
done
scripts/eval.sh test            # every suite
demo/run-demo.sh --check-script # judge-facing claims vs data
cd <repo> && git worktree remove --force ../<repo>-integ-<hhmm>
```
Name the **pair** behind each failure: merge the two suspect PRs alone to confirm it. Semantic collisions,
where data changes and a spoken claim goes stale (#46 → Beat 7), count as failures.

## Dispatch template
```
You are the INTEGRATION-CHECK child agent for an authorized hackathon team (CrowdStrike x SCU, Track 3).
Common rules: prompts/archetypes/_common.md. Spec: prompts/archetypes/integration-check.md.
Clock: deadlines are PDT; check with `TZ=America/Los_Angeles date` (machine clock is CDT, bare `date` is 2 h ahead).
Open PRs in merge order: <list>. Throwaway worktree, never push. Report on issue #<N>, ending <!-- orchestrator-reply -->.
End with the report URL and STATUS.
```
