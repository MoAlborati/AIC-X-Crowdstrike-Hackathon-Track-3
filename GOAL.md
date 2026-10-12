# GOAL — Track 3 Autonomous Build Loop

**North star:** Win CrowdStrike Track 3 ("Secure: Attack & Defend the Agent") with a <3-minute
live demo of **SentinelProxy** — an inline, tool-boundary detection-and-response guardrail for AI
agents (a working slice of CrowdStrike Falcon AIDR) that detects and blocks indirect prompt
injection and data exfiltration against the provided DVAA target, and emits Falcon/AIDR-shaped
alerts mapped to MITRE ATLAS + OWASP.

Full rationale: `planning/STRATEGY.md`. Evidence/citations: `planning/RESEARCH.md`.

## Official brief (verbatim — the judging source of truth)
Source: organizers' slides, transcribed verbatim by @c-awad in issue #128 (2026-10-12). These replace the earlier "AgentWorks
hackathon rules" proxy criteria (now superseded; see `planning/RESEARCH.md` §B).

### Track 3 (official text)
> **CrowdStrike, Track 3: Secure: Attack & Defend the Agent.** Teams either build an AI agent and demonstrate how they'd defend it against prompt injection, tool misuse, or data exfiltration, or attack a provided model/agent with adversarial inputs and build a detector for the exploit. The most advanced track, and the one that maps most directly to what CrowdStrike is building with AgentWorks. Realistic scope for 8 hours: one clear exploit or defense, demoed live rather than a fully hardened system.
> 1st $800 · 2nd $200 · 3rd Prize Box

### Ciocca Venture Award (separate award, official text)
> The Ciocca Venture Award, presented in partnership with SCU's Ciocca Center for Innovation and Entrepreneurship, recognizes the team whose AI-powered cyber defense solution shows the strongest potential to become a real product or venture. Teams are judged on the clarity of the problem they're solving, who would use and pay for their solution, how it stands apart from existing tools, and a credible path from prototype to launch, alongside a working demo.
> 1st $1000 · 2nd $500 · 3rd Prize Box

## How we map to the brief (honest)
- **"One clear exploit or defense, demoed live"** maps to one defense: SentinelProxy at the tool boundary.
  - **Live:** the only live beat is the proxy's benign **HTTP 200** (forwarded untouched), then DVAA's aim-ab request
    **HTTP 403**, blocked pre-forward.
  - **Recorded:** default-deny egress at the tool boundary is the control that actually stops data leaving (RepoBot/RAGBot
    exfil, attacker server received nothing). On stage we say "recorded" for it.
- **"Attack a provided model/agent … and build a detector"** is Path B (DVAA), our main demo.
- **"Build an AI agent and demonstrate how they'd defend it against prompt injection, tool misuse, or data
  exfiltration"** is Path A: OpsBot (`track3a/`), our own agent with all three risks, defended by the same unmodified
  proxy. It also fits the brief.
- **"Rather than a fully hardened system"** supports our honest-scope framing (#123). We list our misses in RESULTS.md.
- **Not in the brief:** DVAA's 22 CTF challenges. Solving them is not judged.
- **Ciocca:** no extra build. If the team targets it (#128, default YES), the deck adds one venture slide covering
  problem, who uses and pays, differentiation vs Falcon AIDR / NeMo Guardrails / Lakera, and path to launch.
  Open: is a separate submission/form needed, and can one project win both?

## Locked decisions (do not relitigate)
- **Path B (main demo):** attack the provided DVAA agent + build a detector. Path A (OpsBot, `track3a/`) is a
  bounded add-on that reuses the same proxy, not a second product.
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
