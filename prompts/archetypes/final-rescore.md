# Archetype: final-rescore / endgame-submit

| | |
|---|---|
| **Purpose** | Two endgame jobs. **Final rescore:** regenerate the headline numbers once, then make every judge-facing file agree with them (claim hygiene). **Endgame submit:** fill the submission metrics, tag the release, and ping the humans who must press submit. |
| **When to dispatch** | Rescore: at the scheduled rescore time (15:00), after the last scoring-relevant PRs merge. Submit: about 15 minutes before the deadline (15:40). |
| **Inputs** | The PRs that must be on main, a pinned clean DVAA checkout (`57918267`), the pitch-framing issue (#38), and the submit issue (#106). |
| **Read / write** | **Write**, in worktree `../<repo>-final`. A data and docs refresh only, so the author may self-merge after `scripts/eval.sh gate <PR#>` is green. |
| **Output** | A PR plus the final headline table posted on the pitch issue (#38), ending `<!-- orchestrator-reply -->`. |
| **Time box** | 25 minutes. The deadline is hard. |
| **Ends** | `STATUS: DONE` with the PR URL and the final table. |

## Final rescore procedure (from the 15:00 run)
1. Confirm the required PRs are on main. If one is missing, note it and proceed anyway.
2. `cd sentinel/scoring && DVAA_SRC=<clean pinned checkout> npm run rescore -- --iterations 15`.
   It must end with `headline.status=ok` and 0 errors.
3. `node scripts/fill-submission-metrics.mjs --video-pending` must fill every placeholder.
4. Consistency check across `results.json`, `RESULTS.md`, `SUBMISSION.md`, the dashboard headline tiles,
   `demo/run-demo.sh --check-script` plus one `--auto`, and `demo/QA-PREP.md`. Fix trivial mismatches and list the rest.
5. **Claim hygiene (mandatory):** every "0% benign FP" is scoped "on the 164-case benign corpus". Wherever
   FP behavior is discussed, add the held-out note: 1/32 hand-written held-out benign docs blocked, 14/16
   paraphrased held-out attacks detected. Held-out sets are labelled held-out and never mixed into the headline.
6. `scripts/eval.sh gate <PR#>`, then self-merge on green. Post on #38: detection, prevention, precision,
   benign FP (T3 vs DVAA), 8 KB evasion count, latency, held-out numbers.

## Endgame submit procedure
1. Re-run step 3 on the final main, open a PR, gate it, and merge it.
2. `git tag v1.0-submission <sha> && git push origin v1.0-submission`.
3. Comment on the submit issue (#106): the tag, the repo link, and the per-track checklist. Agents
   **cannot** submit forms, so a human must.

## Dispatch template
```
You are the FINAL RESCORE child agent for an authorized hackathon team (CrowdStrike x SCU, Track 3).
Common rules: prompts/archetypes/_common.md. Spec: prompts/archetypes/final-rescore.md (follow it exactly,
Clock: deadlines are PDT; check with `TZ=America/Los_Angeles date` (machine clock is CDT, bare `date` is 2 h ahead).
including CLAIM HYGIENE). Quote for the Fact-Forcing Gate: "Final rescore at 15:00".
Freeze <time>; submit by <time>. Required on main: #<A>, #<B>. Post the final table on #38.
End with the PR URL, the final table and STATUS.
```
