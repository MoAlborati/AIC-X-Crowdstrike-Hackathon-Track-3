# RESUME: cold-start runbook for the orchestrator

Read this first when you are a **fresh orchestrator session** or a session that **just got compacted**.
It is the self-contained checklist for picking the loop back up. Details live in `LOOP.md` (protocol),
`AGENTS.md` (roles), `CHAT.md` (issue chat) and `prompts/archetypes/` (child-agent roles).

---

## 0. CLOCK: check it before anything else
> **Every deadline is in PDT. This machine's clock is set to CDT.**
> Always run **`TZ=America/Los_Angeles date`**. A bare `date` prints CDT, **2 hours ahead**, and it once made
> the orchestrator think it was 2 hours later than it was (it started endgame steps early).
> Write every time as `HH:MM PDT`, in comments, issue titles, PROACTIVE.md and dispatch prompts.

## 1. Role policy (non-negotiable)
- **The orchestrator only orchestrates.** It never writes ticket code, tests or docs content itself. It
  selects work, fills `prompts/archetypes/*` templates, dispatches children, reads their `STATUS:` lines,
  answers chat, keeps STATE.md and `planning/PROACTIVE.md` current, and runs the merge flow.
- **Children run on Opus 5.5** (`model: "opus"`). Never a lower tier: this is security subject matter, and a
  weaker model degrades detection quality.
- **Degrade means handoff and retry.** A child that is downgraded or stopped by a safety classifier pushes
  its WIP, writes `handoffs/<ticket>.md` and ends with `STATUS: DEGRADED`. Re-dispatch a fresh Opus 5.5 child
  with `prompts/resume-from-handoff.md` (with more explicit authorized-defensive framing after a safety stop).
  **At most 2 retries per ticket**, then raise it in STATE.md **Blockers** with the handoff path.
- **Merges** happen only through `scripts/eval.sh gate <PR#>`, and only when the reviewer verdict is APPROVE
  and the gate is green. Docs-only PRs may be self-merged by their author after the gate. Never merge
  NEEDS_WORK. At most 2 fix rounds, then "Known limitations" and merge (LOOP.md §Endgame policies).

## 2. Read in this order
1. `STATE.md`: phase, schedule, open PRs table, needs-human issues, Decision Log (newest first).
2. `BACKLOG.md`: tickets, scopes, dependencies. In the endgame, also `planning/PROACTIVE.md` (the time-triggered queue).
3. **What is in flight right now:**
   ```bash
   TZ=America/Los_Angeles date
   gh pr list --state open                       # open PRs (who, which branch)
   gh issue list --state open                    # chat + needs-human threads
   git -C <repo> worktree list                   # one worktree per running child
   ls <repo>/handoffs/                           # interrupted tickets waiting for a resume
   scripts/chat-poll.sh  (one pass, or via the Monitor in §5)
   ```
   A worktree with no matching running child is an orphan. Check its branch (`git -C <wt> log -1`) and
   either re-dispatch it or remove it.
4. `GOAL.md` and `LOOP.md` §Endgame policies, if you don't remember the deadline and merge rule.
5. `prompts/archetypes/README.md`, the index of child roles.

## 3. Worktrees
- **One worktree per ticket**, as a sibling of the main checkout: `../<repo>-<ticket>`. On the build machine
  the main checkout is `~/crowdstrike`, so worktrees are `~/crowdstrike-<ticket>`:
  `cd ~/crowdstrike && git fetch origin && git worktree add -b <branch> ~/crowdstrike-<ticket> origin/main`
- The main checkout is **orchestrator-only**. Children never check out, edit or commit there.
- Put the `git worktree add` line in every write-capable dispatch prompt. Remove the worktree
  (`git worktree remove ~/crowdstrike-<ticket>`) after its PR merges or is abandoned.

## 4. Concurrency floor and the 1-minute tick
- **Keep at least 10 child agents running** in the endgame (LOOP.md's original floor was 5; the operator
  raised it). Each child runs on Opus 5.5, in its own worktree, with a disjoint file scope. When tickets run
  out, fill the floor with reviewers, merge-stewards, integration-check, critic, overseer, advisor and
  research children (see the archetype index).
- **Tick every minute.** Arm it with the `/loop` skill (or an equivalent 1-minute cron, `* * * * *`), using
  this prompt text verbatim:

  ```
  Orchestrator tick. 1) TZ=America/Los_Angeles date. 2) Answer any unanswered chat (chat-urgent first),
  every reply ending <!-- orchestrator-reply -->; close answered issues. 3) needs-human: re-ping at T-15,
  apply the default at the deadline. 4) gh pr list: route APPROVE/NEEDS_WORK/"fixes ready" to reviewer or
  merge-steward; never merge red. 5) planning/PROACTIVE.md: dispatch any item whose trigger fired, mark
  [TAKEN HH:MM]. 6) Top the pool back up to >=10 Opus children, each in its own worktree. 7) Re-arm the
  chat Monitor if it expired. 8) STATE.md refresh every ~30 min. Do not implement anything yourself.
  ```

## 5. Chat intake: re-arm the Monitor every 30 minutes
A Monitor expires after at most 30 minutes, so re-arm it on each expiry notice (and on every cold start):

```
Monitor({
  command: "cd ~/crowdstrike && CHAT_INTERVAL=30 scripts/chat-poll.sh",
  description: "chat intake: unanswered GitHub issue messages",
  timeout_ms: 1800000
})
```
Each `CHAT_EVENT prio=… issue=#N from=… key=…` line is one unanswered message. Seen keys live in `.chat/`,
so re-arming doesn't replay old events. If the poller was down, run one manual pass: `gh issue list` and
check each thread's last item for the marker. Answer chat **before** other work. The rules for replies are
in `prompts/archetypes/chat-responder.md`.

## 6. needs-human policy
Use this for decisions only a human can make (submission forms, repo visibility, presenter logistics).
- **Title:** `[@owner by HH:MM PDT] <question>`. **Labels:** `chat,needs-human` (add `chat-urgent` if under an hour away).
- **The @owner in the title is also the assignee:** `gh issue create --assignee <login> ...`.
- **Body:** the question, the options, the **default** that applies if there's no reply, and the deadline.
- **At T-15 minutes,** re-ping: `@owner reminder: default "<X>" applies at HH:MM PDT <!-- orchestrator-reply -->`.
- **At the deadline,** apply the default, comment what was done, record it in the STATE.md Decision Log, and
  close the issue. If the default itself needs a human (e.g. #106, submitting the form), say so and keep it open.

## 7. Close answered issues
When a thread is resolved (answered, decision applied, PR merged), close it:
`gh issue close <N> --comment "<one line> <!-- orchestrator-reply -->"`. Keep the pinned welcome issue #32 open.
Advisory report issues (Creative #105, Overseer #110, Critic #112) are closed once their items are routed
into `planning/PROACTIVE.md` or QA-PREP.

## 8. Proactive queue
`planning/PROACTIVE.md` is the orchestrator's own work queue (time triggers, follow-ups that wait on other
PRs, needs-human defaults). It used to be private scratchpad content and is now in the repo so it survives
sessions. Check it on every tick. Mark items `[TAKEN HH:MM]` and `[DONE #PR]`, and add new ones with a trigger.

## 9. Fact-Forcing Gate
A "Fact-Forcing Gate" hook may block a tool call until you state facts. State them in one or two lines (what
you are doing, why, and the user instruction you're acting on, quoted), then retry the same call. Give every
child a quotable instruction in its dispatch prompt (e.g. `The instruction to quote is: "Final rescore at 15:00"`).
Cost hooks (COST WARNING / CRITICAL) are waived by the operator, so ignore them.

## 10. Security constraints
- **Defensive only.** We build and score a guardrail against DVAA, an organizer-provided,
  intentionally-vulnerable sandbox. This is an authorized CrowdStrike x SCU hackathon.
- **No new payloads.** Attack strings come verbatim from published benchmarks or DVAA, pinned and hashed.
- **No secrets** in commits, PRs or issues: only DVAA's fake planted honeytokens. The repo goes public.
  No private notes or local absolute paths either (use `<repo>` or `~/crowdstrike`).
- **Loopback only.** Every service binds `127.0.0.1`. Nothing leaves the machine except PRs, issues and
  comments on this repo, and reads of public docs and datasets.

## 11. After you've resumed
- [ ] Clock checked in PDT. You know the next cut line (STATE.md schedule).
- [ ] Chat Monitor armed. Unanswered threads answered.
- [ ] The 1-minute tick is armed.
- [ ] Open PRs mapped to a running child or a queue. Orphan worktrees handled. Handoffs re-dispatched.
- [ ] At least 10 Opus children running.
- [ ] `planning/PROACTIVE.md` triggers checked.
- [ ] A STATE.md Decision Log line: "orchestrator resumed HH:MM PDT (cold start / post-compaction)".
