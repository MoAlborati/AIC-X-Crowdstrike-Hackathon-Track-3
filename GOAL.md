# GOAL — Track 3 Autonomous Build Loop

**North star:** Win CrowdStrike Track 3 ("Secure: Attack & Defend the Agent") with a <3-minute
live demo of **SentinelProxy** — an inline, tool-boundary detection-and-response guardrail for AI
agents (a working slice of CrowdStrike Falcon AIDR) that detects and blocks indirect prompt
injection and data exfiltration against the provided DVAA target, and emits Falcon/AIDR-shaped
alerts mapped to MITRE ATLAS + OWASP.

Full rationale: `planning/STRATEGY.md`. Evidence/citations: `planning/RESEARCH.md`.

## Locked decisions (do not relitigate)
- **Path B:** attack the provided DVAA agent + build a detector. Not building our own victim.
- **Product:** reverse-proxy guardrail in front of DVAA's OpenAI-compatible `/v1/chat/completions`.
- **Stack:** Node.js (match DVAA, Node >=24), vanilla-JS dashboard. Zero heavy deps unless a ticket says so.
- **Target runs OFFLINE** (deterministic canned responses, no API key). Dashboard :9000, agents 7001-7023.
- **Demo = deterministic replays** from `captures/`. No live LLM calls or 2.65M-row dataset scans on stage.

## Definition of Done (the winning minimum)
1. DVAA runs; one exploit reproduced, exfiltrating a planted secret, visibly **evading DVAA's own
   8KB-head/tail baseline scanner**.
2. SentinelProxy **detects + BLOCKS** the same attack; honeytoken tripwire fires deterministically.
3. A **Falcon/AIDR-shaped alert** renders, tagged MITRE ATLAS + OWASP LLM01/02/06 + Agentic ASI01/02 + OASB-1.
4. **Incident graph** shows the taint path source->sink; **latency** number displayed (mirror "sub-30ms").
5. **Scoring table:** precision/recall vs DVAA's `dvaa{}` ground-truth labels + median latency.
6. Same attack **fails** against the AIM-defended twin (7014) and SecureBot (7001) — secure-by-design contrast.
7. `demo/SCRIPT.md` rehearsed under 3 minutes; fallback video recorded.

## Non-goals (explicitly out of scope)
- Hardening a full system; NeMo/CaMeL/general taint analysis (cite as slides, don't build).
- A fifth feature after the DoD is met. Freeze and rehearse.
- Any outward-facing action beyond the authorized hackathon target.

## Success metric for the loop
Every DoD item is backed by a merged PR that passed its gates (`gates/`), and STATE.md shows the
demo rehearsed green. Stretch items only after all 7 DoD items merge.
