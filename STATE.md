# STATE — living loop state (source of truth; update every iteration)

> This file survives context compaction. Any agent resuming the loop reads GOAL.md + LOOP.md + this.
> Keep it terse and current. Append to the Decision Log; overwrite the Status block.

## Status (overwrite each iteration)
> **Cold start? Read [`RESUME.md`](RESUME.md) first.** It is the orchestrator runbook. All times are PDT, and this machine's clock is CDT:
> always run `TZ=America/Los_Angeles date`.

- **As of:** 2026-10-12 **14:03 PDT**. `main` = **`1a6df68`** (Merge #133). **Submit by 15:55 PDT (deadline 16:00). Present 18:00 PDT.**
- **Phase:** ENDGAME. Land the open PRs that are gated green before the 15:15 freeze, then the final rescore (15:00) and the delivery gate.
  Operator directive: **"keep the overseer running testing and evaluating."**
- **Presenter:** Catherine (c-awad), from her Mac (bash 3.2, Colima) over screen share (#39, #51).
- **Submissions (#63):** Track 3 = Path A (`track3a/` OpsBot) + Path B (SentinelProxy), ONE submission. Track 1 = `track1/`
  SOC analyst tool, a separate submission. Form submission: #106.
- **Open PRs (`gh pr list`, 14:02 PDT):**
  | PR | Branch | What |
  |---|---|---|
  | #136 | flake-fix | Timing asserts → CPU time (whole class) + proxy request_id scrub bug behind pipeline flakes |
  | #135 | sec-126-routes | Proxy: honeytoken backstop on every route + refuse canary-bearing non-chat POSTs (#126 finding 1) |
  | #134 | venture | Docs: Ciocca venture slide + SUBMISSION "Product & venture" + QA-PREP Q&A (#128) |
  | #127 | hyg-a | Hygiene (#112 critic C safe items): /tmp-clone tests, capture cap 2000, egress warn visibility, drop spike/ |
  | #122 | t3-normalize | T3: re-join spaced-out identifiers before destination + honeytoken matching (#112) |
  | #117 | gate-demo | `eval.sh gate`: demo checks + claim-drift check (#110) |
  | #115 | t13-layered | Derived "T3 blocks, DVAA queues" lens in RESULTS.md |
- **Recent merges (12:30–14:02 PDT):**
  - #133: post-merge review fix for #114/#109. The snapshot scan now covers tracked-but-gitignored and export-ignore files, the allowlist can no longer mask a real key, the `sk-` regex is widened, and main passes the scan.
  - #132: official Track 3 + Ciocca brief.
  - #125: chat-poll.
  - #121: pitch reframe.
  - #120: Track 1 held-out refresh.
  - #119, #116, #102 and #98: PRESENTER / Beat 7.
  - #118: harness archetypes + RESUME.md.
  - #114: `make-submission-snapshot.sh`.
  - #113: track3a output dir.
  - #111: Track 1 SOC Brief UI.
  - #109: `eval.sh test` gates scripts/ and flags UNGATED.
  - #108: SUBMISSION metrics.
  - #107 and #101: Track 1 AMiner + held-out.
  - #103: soc-handoff.
  - #99: Track 1 severity.
  - #97: stage capture 4, egress block.
  - #87: Track 1 SUBMISSION draft.
- **Gate health:** `scripts/eval.sh test` on #133's tree (= `main` `1a6df68`): all 14 suites PASS. Wall-clock latency asserts in `sentinel/alerts` and
  `sentinel/proxy` flake under host load (load avg 35–50 on 22 cores) and pass on isolated rerun. #136 fixes the class. Run the
  delivery-gate replays on a quiet host.
- **Open needs-human issues:**
  - #55: presentation format, @c-awad by 14:30.
  - #66: demo video REQUIRED, record 15:20–15:40, @c-awad by 15:50.
  - #73: repo visibility. HOLD until Mo says go, with no auto-default (@MoAlborati). Snapshot tool: `scripts/make-submission-snapshot.sh`, never pushes.
  - #85: delivery gate on Catherine's Mac, @c-awad 15:15–15:40.
  - #106: SUBMIT the form(s), Track 3 + Track 1, @c-awad by 15:55.

### Remaining schedule (PDT)
| Time | Work |
|---|---|
| now–15:00 | Gate + merge the open PRs (max 2 fix rounds each; leftovers → "Known limitations"); overseer keeps testing/evaluating |
| **15:00** | **Final rescore** (`sentinel/scoring/RESULTS.md` + `results.json`); SUBMISSION/pitch numbers re-synced from it |
| **15:15** | **CODE FREEZE** + delivery gate (≥5 clean replays) on `main` AND on Catherine's Mac (#85); demo video 15:20–15:40 (#66) |
| **15:45** | Tag `v1.0-submission` (snapshot via `scripts/make-submission-snapshot.sh`; publishing waits on #73) |
| **15:55** | **Submit** the forms (#106); deadline 16:00 |
| **18:00** | **Present** (Catherine, screen share) |

### Honest metrics (`sentinel/scoring/results.json`, generated 20:10Z = 13:10 PDT; 353 cases: 189 attack / 164 benign; 0 errors)
| System | Detection | Prevention | Benign FP |
|---|---|---|---|
| SentinelProxy T3 | 67.7% (128/189) | 41.8% (79/189) | **0.0% (0/164)**, precision 100% |
| DVAA baseline | 65.6% (124/189) | 63.0% (119/189) | 12.8% (21/164) |
- T3 rule-intent block (legacy `recall`) is 44.4% (84/189). T3 latency: median 0.08 ms, p95 0.42 ms.
- T3 catches and prevents both cases that evade DVAA's 8 KB scan window (2/2). Any recall DVAA has beyond that comes with a 12.8% benign FP rate.
- Held-out results:
  - Benign: 1/32 blocked, and 4/32 raise an alert without a block.
  - Attacks: 14/16 hand-written paraphrases detected, but only 1 of a reviewer's 6 further paraphrases. Recall on novel phrasing is limited (#46).
- These numbers are pre-rescore. #122, #115 and #135 may move them, and the 15:00 rescore is authoritative.

## Backlog pointer
See BACKLOG.md and RESUME.md. Next: gate and merge the open PRs (#136 first, because it de-flakes the gate). Then the 15:00 rescore, the 15:15 freeze and delivery gate, the 15:45 tag, and the 15:55 submit.

## Decision Log (append-only, newest first)
- 2026-10-12 14:02 PDT — **Post-merge review of #114/#109 → #133 merged.** #114's public-release scan skipped
  tracked-but-gitignored and export-ignore files, let a fake-prefix + real-suffix key through the allowlist, and missed
  `sk-proj-` keys containing `_`/`-`. Main itself failed the scan on one internal word. All fixed with a real-seam test
  (RED on #114's script, GREEN on #133). In #109, a gitignored dir with test files gave a false UNGATED FAIL; fixed in #133.
- 2026-10-12 ~13:00 PDT — **Schedule change (#39):** submit by 16:00, present at 18:00. Code freeze moves 14:30 → **15:15**.
  Final rescore at **15:00**. Delivery gate **15:15–15:45** on `main` AND on Catherine's Mac. Submit by **15:55**.
  Slides and rehearsal 16:00–18:00. LOOP.md "Endgame policies" updated to match.
- 2026-10-12 — **Presenter and machine (#39, #51):** Catherine (c-awad) presents from her Mac over screen share. Mac: M4 Pro
  arm64, macOS 26.6.2, Colima, stock bash 3.2, Node 26 → move to node@24. Mac QA issues #58–#61 are routed.
- 2026-10-12 — **Tracks (#63):** multiple tracks are allowed, each as its own submission. Track 3 Path A (`track3a/`,
  OpsBot, PR #62) and Path B (SentinelProxy) ship as ONE submission. Track 1 (Shruti, `track1/`, #64/#68) is a separate
  submission, with advisor agents reviewing it every ~30 min.
- 2026-10-12 — **Canonical proxy (#37):** the `.mjs` proxy (#14) is canonical. Consolidation PR #67 (merged, via its steward) retires the #21 `.js` proxy.
- 2026-10-12 — **One orchestrator (#36):** Shruti's loop is off; this loop is the only orchestrator. #23 is closed at 13:00.
- 2026-10-12 — **Pre-public (#40):** no secrets in tree or history. Local paths scrubbed (#44); other-project references
  scrubbed (#48). Shruti's commit email is OK. Benchmark exfil targets kept verbatim (default). Recommendation: squash-publish
  after the hackathon.
- 2026-10-12 — **Pitch framing (#38):** deferred until the 15:00 final rescore. Pure-injection policy = **alert** (not block).
- 2026-10-12 — **Submission (#52):** no submission format found in the DVAA repo. SUBMISSION.md drafted and merged (#69); tag
  `v1.0-submission` planned for 15:45.
- 2026-10-12 — **Process (endgame):** chat intake via issues (#32/#33); 1-minute orchestrator tick ("orchestrator should
  always be active and working"); serial merge queues (queue 2: #49 → #46, queue 3: #56 → #62; #62 merged first); every `needs-human` issue
  names an owner, a deadline and a default. A mock judge review drove the stage fixes (#49, #50, T5-stage).
- 2026-10-12 — **CPU-time timing test fix (in flight; first step #42 merged):** the T3 timing test now bounds CPU time (40 ms), not
  wall clock, because wall-clock timing flaked under parallel gate load. #27's cap/dedupe work is folded into T3-fix.
- 2026-10-12 — **Metric split: detection vs prevention.** Response-side checks are alert-only (T8), so we report
  detection (alert raised) and prevention (request blocked pre-forward) separately, with benign FP as the headline. No blended numbers (#28).
- 2026-10-12 — **Two orchestrators (#36).** A teammate's loop (#23) and this loop were both active. We asked the
  operator in #36 to pick ONE. Until they answer, this loop leaves #23 alone and avoids its files.
- 2026-10-12 — **Serial merge queue:** to stop each merge from breaking the next PR, merges go one at a time, each
  re-gated against fresh main (`scripts/eval.sh gate`): #41 → #35 → #26.
- 2026-10-12 — **1-minute orchestrator tick:** the ~10-minute heartbeat dropped to 1 minute for the endgame (chat,
  PR reviews, CI). "orchestrator should always be active and working".
- 2026-10-12 — **Chat intake via GitHub Issues (#32, PR #33):** humans talk to the loop through `chat`-labelled issues;
  a poller picks them up, and `needs-human` marks operator decisions (CHAT.md).
- 2026-10-12 11:58 PDT — **Endgame decisions (operator).** Operator's direction: "limit scope, our goal is to win the hackathon".
  1. **Deadline 16:00 PDT.** Schedule in the Status block. **Feature freeze 14:30.**
  2. **Merge authority:** a reviewer or merge-steward agent may merge a PR once its reviewer verdict is APPROVE and its tests are green.
     Humans can still review at any time.
  3. **Review-round cap:** at most 2 fix rounds per PR. Anything still open after that goes under "Known limitations" in the PR, then merge.
  4. **T3 scope frozen** to the demo-critical minimum: honeytoken tripwire, destination provenance, full-payload fail-closed
     request-side scan, and T4 verdicts. Everything else in T3 becomes stretch.
  5. **Architecture finding (T8):** DVAA agents execute tools in-process, so the proxy can prevent only request-side (pre-forward)
     attacks. Response-side checks are alert-only. The pitch claim is decided after the egress spike.
  6. **Repo visibility:** judges will get access, and the repo goes public later. Presentation materials and the video come at the end.
- 2026-10-12 — Branch policy: all ticket PRs target `main` from now on. #2, #4 and #5 had merged into stacked base branches, so their content was off `main`; this catch-up PR lands T0b, T0c and T1.
- 2026-10-12 — T1 DONE (PR #5, attempt 2). It captured 3 attack fixtures (RAGBot A/B, RepoBot, FlightBot) and 6 benign ones. Headline pair: RAGBot 7005 ↔ RAGBot-AIM 7014. The optional LegacyBot/SecureBot pair is deferred: it hit a safety stop, and acceptance (≥3 attack fixtures) is already met.
- 2026-10-12 — **Concurrency floor (operator directive):** replaces the "at most 3 implementer agents" cap with
  **minimum 5 concurrent child agents**, all Opus 5.5, each in its own worktree on a disjoint file scope. When fewer than 5
  tickets are unblocked, run tickets stacked on in-review branches plus research, review and test agents. The orchestrator is always
  working and runs a **~10-minute heartbeat** that checks PR reviews and comments (LOOP.md §Parallelism, §How the loop keeps
  running; AGENTS.md; prompts/orchestrator-kickoff.md; BACKLOG parallel-waves note).
- 2026-10-12 — **Worktree rule:** every concurrently running ticket MUST use its own `git worktree` at
  `../<repo>-<ticket>`, and the main checkout is orchestrator-only. Cause: an incident where agents shared the main checkout
  and a commit landed on another agent's branch (LOOP.md §Worktrees, AGENTS.md, all `prompts/*.md`).
- 2026-10-12 — **Cost-waiver line** added to every `prompts/*.md`: the operator has waived cost limits, so child agents ignore COST
  hook messages and finish (cost hooks had cut several T0c research reports short, and many of their citations are unverified).
- 2026-10-12 — **T1 attempt 1 ended DEGRADED:** a safety-classifier stop, plus the build machine's Node 22 is below DVAA's
  required Node ≥24. Re-dispatched with DVAA run **via Docker** instead of the host Node.
- 2026-10-12 — T0c adjacent-knowledge round 2 (`planning/ADJACENT.md` §10, PR stacked on #2): eight more domains plus
  an empirical transfer-cases study. **Framing revised:** matching actor roles is neither necessary nor sufficient. The predictors are a
  comparable choke point and adversary adaptation relative to feedback, and actor roles mainly locate the choke point. Backlog: T3 gains
  the **user-turn mandate** (signed `{tool, destination, max_amount, expires}` from principal turns only), merged with
  destination provenance and per-tool policy into one `policy.json`. T7 gains **per-rule override-rate tracking**
  (CPOE 49–96% overrides, so hard-block a narrow tier, human-only override). New stretch tickets: S10 tool-manifest lockfile + capability
  diff, S11 counterfactual re-plan explainer (MELON, ICML 2025), S12 cross-session campaign correlation.
- 2026-10-12 — T0b adjacent-knowledge analysis (`planning/ADJACENT.md`, PR stacked on #1): a field counts as adjacent
  by structural match (confused-deputy triad, shared data/control channel, choke point, adaptive adversary),
  not surface similarity. Top sources are software injection and BEC; immunology and HACCP are narrative only. Folded the convergent
  deterministic mechanisms into T3/T4/T5/T7 (destination provenance, source→sink rule, canaries + seeded
  fake records, fail-closed, per-tool policy report-only/enforce, cumulative caps, narrative case card,
  benign FP rate as headline metric). Added stretch S5–S9. **Excluded learned behavioral baselines** (no history).
- 2026-10-12 — Model policy set: orchestrator = main Opus 5.5 session (non-implementing); all ticket work
  by child agents dispatched `model: "opus"` (Opus 5.5); degradation/safety-stop → handoff file +
  re-dispatch fresh Opus 5.5, max 2 retries then operator (LOOP.md §Model policy, AGENTS.md).
- 2026-10-12 — GitHub remote set: origin = shrutidoshi94/AIC-X-Crowdstrike-Hackathon (we have WRITE).
  Remote blocker resolved. T0 setup raised as reviewable PR off `t0-goal-loop-setup`.
- 2026-10-12 — Pivoted from "paste-prompt" deliverable to autonomous PR-driven goal loop (operator request).
- 2026-10-12 — Path B locked; SentinelProxy reverse-proxy design chosen; DVAA mapped (see STRATEGY §4).
- 2026-10-12 — 5-agent parallel recon complete; strategy + research docs written.

## Metrics (update as tickets land)
| DoD item | Ticket | PR(s) | Status | Notes |
|---|---|---|---|---|
| 1 Exploit+evasion | T1, T6, T6b | #5, #10, #15, #29, #31 | MERGED | Corpus 353 cases (189/164); #31 fixed exfil labels |
| 2 Detect+block | T2, T3, T3-fix, T3-recall | #14, #21, #24, #41, #42, #67; #56, #46 open | MERGED core; queues 3 (#56) and 2 (#46) | Request-side block only; `.mjs` canonical (#37 → #67) |
| 3 AIDR alert | T4, T10 | #3, #12, #26 | MERGED | #26 wires verdicts → alerts → dashboard |
| 4 Incident graph | T5, T5-lens | #11; #49 open | MERGED; #49 heads queue 2 | Headline Detected/Prevented vs DVAA (mock judge review) |
| 5 Scoring | T7, T7-real | #13, #28 | MERGED | 67.7% / 41.8% / 0 FP (on the 164-case benign corpus) with #46 merged |
| 6 Secure contrast | T8, spike, T12, T12-live | #16, #18, #22, #45; #57 open | MERGED; #57 self-merge | Response-side alert-only; egress enforced at tool boundary |
| 7 Demo script | T9, T9-fix | #9, #35, #65; #50 open | MERGED; #50 self-merge | Presenter Catherine (Mac); video #66 |
| Track 3A | OpsBot | #62 | MERGED | Same submission as Path B (#63) |
| Submission | docs | #69 | MERGED | Tag `v1.0-submission` at 15:45 |
| Infra | T11, chat | #20, #33 | MERGED | One-command eval + merge gate; Mac QA #58–#61 |
