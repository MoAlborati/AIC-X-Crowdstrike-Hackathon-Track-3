# Tester Gate — test validity (must be GREEN before reviewer gate)

Run by the Tester child agent. Tests must exercise the **real feature on real/data-rich inputs**, not a
mock of the thing under test. Encodes the firm's test-validity + delete-the-fix rules. RED → back to Build.

## Real seams (no mocking the feature under test)
- [ ] The detector / proxy / scoring code runs for real against a **real DVAA port or a real captured
      transcript** (incl. the real `dvaa{}` ground-truth block) — not a hand-stubbed response.
- [ ] Mocking a *dependency* for speed is OK; mocking the *feature itself* (the detector, the planner-like
      verdict path, the parser) is NOT — that is a test of the mock.
- [ ] Captures/fixtures are parsed the same way production parses them (no dict-shaped shortcut that the
      real parser would reject).

## Data-rich fixtures (project-specific)
- [ ] Includes a payload **>8KB** whose exfil signal sits **outside** the first/last 8KB (beats DVAA's
      baseline) — proves the full-payload scan.
- [ ] Includes a **multi-hundred-row** tool output (data-rich, not 2–3 rows).
- [ ] Oversize-input case asserts a **loud ALERT/raise**, never a silent truncation.
- [ ] Decision-path lookups tested at scale (a target entity/token present beyond any display cap is
      still found).

## Latency
- [ ] Latency is **measured** and recorded (median + p95) for detection/scoring on the data-rich corpus.

## Delete-the-fix proof (for any bug fix)
- [ ] With the fix removed, the test is **RED** on data-rich data across **≥3 runs** (not a flake).
- [ ] With the fix applied, the test is **GREEN**.
- [ ] Residual-cap audit: after fixing a cap/bound bug, other sites using the same pattern were scanned.

**Verdict:** GREEN only if all applicable boxes pass. Record run counts + latency numbers in the PR.
