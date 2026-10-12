# Reviewer Gate — adversarial self-review (before the PR opens)

Run by the Reviewer child agent after the tester gate is GREEN, so the operator's review starts clean.
Review adversarially: assume the data grows and the attacker adapts.

## Silent-degradation audit (team data-scale reliability rules)
- [ ] Grep the diff for dynamically-assembled scans/buffers/lists without a cap → each must have a hard
      cap + fail-loud on overflow. No silent truncation anywhere (we are beating DVAA's 8KB gap).
- [ ] Every `limit=N` / slice / head-tail in the diff: is it a **decision** site (must be
      pool-size-independent / full scan) or a **display** site (cap OK, labeled)? Flag any decision site
      using a capped scan as NEEDS_WORK.
- [ ] Each new cap/bound has its failure mode documented (PR "bounds introduced" section).

## Correctness & scope
- [ ] Code matches the ticket's acceptance criteria and stays within its declared file scope.
- [ ] Honeytoken/taint/egress logic keys on robust signals, not one brittle exact injection string
      (the honeytoken is the deterministic anchor; heuristics must generalize to variants).
- [ ] Framework tags (MITRE ATLAS/ATT&CK, OWASP LLM, Agentic ASI, OASB) are accurate per RESEARCH.md.

## Safety & hygiene
- [ ] No real secrets in the diff — only DVAA's fake planted honeytokens.
- [ ] No outward action beyond this repo + the authorized local DVAA target.
- [ ] Tests from the tester gate are present and real-seam (not mocks of the feature).

**Verdict:** APPROVE / NEEDS_WORK. On NEEDS_WORK, list findings; implementer fixes and re-runs tester gate.
