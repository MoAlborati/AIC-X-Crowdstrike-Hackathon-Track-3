# SE Gate — spec & design review (before Build)

Run by the orchestrator/implementer before writing code for a ticket. Goal: the ticket's spec,
acceptance criteria and **bounds** are explicit, so nothing silently degrades as data grows. Encodes the
team's data-scale reliability rules (bounded/fail-loud, data-rich testing, delete-the-fix proof).

If any box can't be checked, do not guess — raise it in STATE.md **Blockers** and stop.

## Spec clarity
- [ ] Ticket id, DoD item, deps, and **file scope** are stated (file scope must be disjoint from other
      in-flight tickets — parallelism rule in LOOP.md / BACKLOG.md).
- [ ] Acceptance criteria are concrete and testable.
- [ ] The real seam this ticket touches is named (which DVAA port, which capture, which detector verdict).

## Bounds & fail-loud (firm rule: bounded + fail-loud on overflow)
- [ ] Every input the code assembles or scans has an explicit **cap** (request body, tool-output rows,
      scan window, alert payload, graph node count).
- [ ] On overflow the behavior is **fail-loud**: raise/ALERT with `{size, cap, action}` logged.
      **Never silently truncate** (DVAA's 8KB head/tail scan is the anti-pattern we beat — do not copy it).
- [ ] Each cap is documented with **why that value** and **what happens beyond it** (error / alert /
      queue / reject — never silent-fail). Record it in the PR "bounds introduced" section.

## Resolution vs display caps (firm rule: no capped list scan for decisions)
- [ ] Any value used for a **decision** (detector verdict, taint flag, routing, block) is computed over
      the **full** data or via a targeted lookup — not a capped list scan (`limit=N` then search within).
- [ ] Caps that exist only for **display/pagination** (dashboard feed, graph render budget) are labeled
      as intentional UX limits and are NOT on a decision path.

## Data-rich by design
- [ ] The design is validated against **data-rich** inputs — the real DVAA fleet + payloads >8KB and
      multi-hundred-row tool outputs — not toy 2–3 row fixtures.

**Verdict:** PASS only if every applicable box is checked (mark N/A for docs-only tickets).
