<!-- SentinelProxy — Track 3 DVAA defense. One ticket = one PR. Do not merge without operator approval. -->

## Ticket
<!-- e.g. T3 — Detector core. Link BACKLOG.md entry. -->

## DoD item
<!-- Which GOAL.md Definition-of-Done item(s) this advances (1–7), or "setup / n-a". -->

## Summary
<!-- What changed and why, in a few lines. -->

## Gate evidence
- [ ] **SE gate** (`gates/se-gate.md`) — spec/bounds explicit *(or N/A: ______)*
- [ ] **Tester gate** (`gates/tester-gate.md`) — GREEN: real seams + data-rich fixtures + latency + delete-the-fix proof *(or N/A: ______)*
- [ ] **Reviewer gate** (`gates/reviewer-gate.md`) — APPROVE (adversarial self-review done) *(or N/A: ______)*
- [ ] **Delivery gate** (`gates/delivery-gate.md`) — live-drive on real DVAA fleet / ≥5 clean replays *(or N/A: ______)*

## Bounds introduced + failure modes
<!-- List every cap/limit/window this PR adds. For each: the value, why, and what happens on overflow
     (must be fail-loud: raise/ALERT — never silent truncation). Firm rule. "None" if none. -->

## How to verify locally
<!-- Exact commands: bring up DVAA target port(s), run the proxy/detector/tests, replay captures. -->

## Model that produced this
<!-- e.g. Opus 5.5 (claude-opus-5-5). Note any degradation/handoff/resume during the ticket. -->

---
🤖 Generated with [Claude Code](https://claude.com/claude-code)
