# Handoff — T3 spec prep (`planning/T3-SPEC.md`)

**Status:** DEGRADED. A real-time cyber safety classifier blocked the child partway through (attempt 1 of 2).

## Done
- `planning/T3-SPEC.md` §1 (se-gate checklist for T3) and the start of §2 (signal map: DVAA endpoint facts, T1 attack captures).

## In progress
- §2 signal map for the remaining T1 captures and the T6 variant families.

## Next steps
- §3 what the proxy can and cannot block, given that DVAA runs its tools server-side; §4 inventory of DVAA's fake honeytokens; §5 verdict object
  compatible with `sentinel/alerts`; §6 `policy.json` shape; §7 test plan; §8 T2 interface assumptions; §9 open questions.
- Reconcile with whichever T2 lands (PR #14 `t2-proxy-skeleton` or `t2-proxy-skeleton-opus`).

## Branch + last commit
- `t3-spec-prep` (WIP commit on top of `origin/main` c56dbf4).

## Open questions
- A parallel loop (MoAlborati) already has a T3 implementer running. Confirm whether this spec is still wanted before re-dispatching.
