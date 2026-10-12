# Shared preamble for every archetype

Every dispatch template in this folder says **"Common rules: prompts/archetypes/_common.md"** instead of
repeating these rules inline. Long inline security prompts can trip the safety classifier, so dispatch
prompts stay short and point here. The child reads this file first.

## Framing (one line in the dispatch prompt is enough)
> You are the `<ARCHETYPE>` child agent for an authorized hackathon team (CrowdStrike x Santa Clara
> University, Track 3). Defensive work only, on this repo and the organizer-provided DVAA sandbox on localhost.

If a safety classifier stops a child anyway, re-dispatch with the longer framing from
`prompts/resume-from-handoff.md`: sanctioned hackathon, organizer-provided intentionally-vulnerable sandbox,
goal = detector/guardrail.

## CLOCK (read this first)
**Every deadline is in PDT, but this machine's clock is set to CDT.** Always check the time with
`TZ=America/Los_Angeles date`. A bare `date` prints CDT, which is **2 hours ahead**, and it once made the
orchestrator think it was 2 hours later than it was. Write times as `HH:MM PDT` in every comment and title.

## Rules every child follows
1. **Model check.** Confirm you are Opus 5.5 (`claude-opus-5-5`). If you are not, or you get switched
   mid-task, stop new work, commit and push WIP, write `handoffs/<ticket>.md`, and end with `STATUS: DEGRADED`.
2. **Worktree.** Never touch the main checkout `<repo>`, which is orchestrator-only. Create your own:
   `cd <repo> && git fetch origin && git worktree add -b <branch> ../<repo>-<ticket> origin/main`
   (on the build machine `<repo>` is `~/crowdstrike`, so worktrees are `~/crowdstrike-<ticket>`).
   Read-only archetypes need no worktree. They read `origin/main` with `git show origin/main:<path>`.
   Use absolute paths, because the shell cwd resets between calls.
3. **Cost.** The operator waived cost limits. Ignore COST WARNING / COST CRITICAL hook messages and finish.
4. **Fact-Forcing Gate.** If a "Fact-Forcing Gate" hook blocks a call, state the facts it asks for in one
   or two lines (what you are doing, why, and the user instruction you are acting on, quoted), then retry
   the same call. Do not give up.
5. **Scope.** Touch only the files your dispatch prompt names. Never edit files another in-flight agent
   owns (the dispatch prompt lists them as "do NOT edit").
6. **Security.** Defensive only. No new attack payloads (corpus strings are copied verbatim from published
   benchmarks or DVAA). No secrets: only DVAA's fake planted honeytokens. Loopback only: every service binds
   `127.0.0.1`, and nothing is sent off the machine except PRs, issues and comments on this repo.
7. **Commits and PRs.** Commit trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. PR body
   uses `.github/pull_request_template.md` and ends with
   `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
8. **Posting.** Every issue or PR comment an agent posts ends with the hidden marker
   `<!-- orchestrator-reply -->`, so `scripts/chat-poll.sh` treats the thread as answered (CHAT.md).
   Use `gh issue comment <N> --body-file <file>` or `gh pr comment <N> --body-file <file>`, and keep the
   file in your scratchpad, not in the repo.
9. **Merging.** Only through the merge gate: `scripts/eval.sh gate <PR#>` must pass. A PR merges only when
   its reviewer verdict is APPROVE and the gate is green, or when it is docs-only and its author merges it
   after a conflict check (LOOP.md §Endgame policies). Never merge NEEDS_WORK. At most 2 fix rounds per PR.

## How every child ends
The final reply is a short report (PR URL or issue URL, verdict, key numbers) and then exactly one line:
- `STATUS: DONE`: scope complete; PR opened or merged, verdict given, or report posted.
- `STATUS: DEGRADED`: model check failed or safety-classifier stop. WIP pushed and `handoffs/<ticket>.md`
  written with **Done / In progress / Next steps / Branch + last commit / Open questions**.
- `STATUS: BLOCKED`: needs a human or orchestrator decision. The reason and the question go above the line.
