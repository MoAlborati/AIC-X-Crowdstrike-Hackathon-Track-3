# Proactive work queue

The orchestrator's queue of work it does **without being asked**: time-triggered items, follow-ups that wait
on another PR, and default actions for needs-human deadlines. It used to live in the orchestrator's private
scratchpad, which a new session or a compaction loses, so it now lives here.

**How to use it**
- On every tick, check whether any item's trigger has fired (a time, a merge, an author saying "round 1 fixes ready").
- When you dispatch an item, mark it `[TAKEN HH:MM]` (PDT, from `TZ=America/Los_Angeles date`). When it lands, mark it `[DONE]` with the PR or issue number.
- Add items as they come up: from chat, overseer, critic and creative reports, or reviewer follow-ups. Each one needs a trigger and an owner.
- Update this file in the next docs PR (for example, the STATE refresh). It doesn't need its own PR.

Snapshot copied at ~13:40 PDT on 2026-10-12. Status markers are as of that time.

1. [DONE #49] T5-lens: dashboard shows detection vs prevention lenses + headline.status (sentinel/dashboard)
2. [TAKEN, recurring] STATE refresh: STATE.md status block/metrics/PR table, refreshed every ~30 min (docs PR)
3. [DONE, reported on #40] Pre-public sanitization scan, read-only: secrets/PII/local paths
4. [SUPERSEDED by 18] Final rescore once T3-fix + T3-recall + T12 merge (was 14:10)
5. [DONE #50] run-demo wiring: point the egress beat at sentinel/egress (spike #18); re-run --auto x5
6. [SUPERSEDED: delivery gate moved to 15:15–15:45, #39] Delivery gate at 14:15
7. [DONE #67] Duplicate proxy cleanup (#14 .mjs vs #21 .js): default #14 applied (#37)
8. T3 recall round 2, if T3-recall leaves misses and time remains before the freeze
9. [FOLDED into 1] Dashboard demo polish: font/zoom for projector (#39)
10. [10b README TAKEN 12:39] Post-freeze: fallback video checklist run-through (human), final README pass for judges
11. [DONE #69] SUBMISSION.md draft + fill-submission-metrics.mjs (fill after the 15:00 rescore)
12. [DONE] 13:00 close #23 (promised to Shruti)
13. [DONE] 13:05 STATE.md refresh #2
14. 15:30 track1 subtree split if Shruti has not answered #64
15. 15:45 tag v1.0-submission + fill SUBMISSION metrics (see 32)
16. Track 1 advisor passes on #68: [13:00 DONE], [13:30 DONE], 14:00, 14:30, 15:00
17. [DONE] Queue 3 round-2 steward for #56 once t3-fix-blockers pushes its round-1 fix
18. 14:45 dispatch final-rescore agent (after #56, #46 merged): `npm run rescore`, `fill-submission-metrics --video-pending`, update #38 (prompt: `prompts/archetypes/final-rescore.md`)
19. [DONE #50] Round-2 steward for #50 once t9-beat4-fix pushes its round-1 fix
20. [DONE #46] Round-2 steward for #46 once t3-recall pushes its round-1 fix (after #56 merges)
21. Next STATE refresh: also fix nits: the ADJACENT.md:125 rule-wording nit (done in #114), the old repo URL in LOOP.md and STATE.md (LOOP.md fixed in the harness-docs PR)
22. After #75 + #76 merge: add live/egress-boundary as stage capture #4 (tool-boundary Blocked) in stage mode + run-demo Beat 4b deep link (#97)
23. After #50 + #70 + #76 merge: refresh demo/PRESENTER.md (drop hedges, final stage URLs, live Beat 4) (#102)
24. ~14:00, after #50 + #76 + #46 merge: mock-judge pass #2 on main (score delta vs 6/7/7/5), last-chance fixes before 15:15 (critic archetype; #112 is the latest teardown)
25. #76 round 2: when its author says "round 1 fixes ready", dispatch a round-2 steward (worktree `../<repo>-r76`). Also chain #97 after #76: retarget its base to main, merge main, gate, merge. Fix the "unattributed agent turn" wording on stage 4 if it's trivial.
26. [DONE #91] CLAIM HYGIENE before the final rescore: "0% benign FP" scoped "on the 164-case benign corpus"; held-out note (1/32 hand-written benign blocked)
27. If time after freeze-safe: lexicon follow-up for the quoted-injection-in-security-memo FP (likely post-hackathon)
28. 14:45 default: draft track1/SUBMISSION.md unless Shruti says no on #68 (#87)
29. 14:45: if no objection from Shruti on #68/#87, mark #87 ready (`gh pr ready 87`), gate, merge
30. [DONE #99] 14:15: if no reply on #94, Track 1 vendor-severity fallback + P1-first queue + README chain wording as ONE PR
31. [DONE: #92 closed, known FP kept] Round-2 steward for #92 or close it by 14:15
32. [TAKEN, #108 open] 15:40 SUBMIT: final-submit agent fills metrics + tags v1.0-submission (#108); humans pinged on #106 to submit the form(s)
33. POST-SUBMIT (16:00–17:45) presentation prep from #105's creative top 3: judge-as-attacker after the 3 minutes (rehearse ~20 bypass attempts first); "Confirmation of Payee for agents" + the we-attacked-ourselves slide; exfil-split framing (80.3% prevented where data actually leaves). Idea #1 (T3 blocks, DVAA queues) missed the freeze, so it's a Q&A talking point only.
34. POST-SUBMIT: route Critic (#112) and Overseer (#110) findings into QA-PREP answers, not code
