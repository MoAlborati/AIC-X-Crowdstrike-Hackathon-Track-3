# CrowdStrike Track 3 — Winning Strategy

**Event:** Collaborate AI × Santa Clara University — CrowdStrike "Track 3: Secure — Attack & Defend the Agent"
**Format:** 8-hour build, **live demo** judged. Prizes: 1st $800, 2nd $200, 3rd prize box.
**Date:** 2026-10-12.

## 0. Official brief (verbatim — judging source of truth)

Source: organizers' slides, transcribed verbatim by @c-awad in issue #128 (2026-10-12). It supersedes the "AgentWorks hackathon rules" proxy
criteria formerly used here and in `RESEARCH.md` §B. Judge-score passes (critic archetype) score against this text.

### Track 3 (official text)
> **CrowdStrike, Track 3: Secure: Attack & Defend the Agent.** Teams either build an AI agent and demonstrate how they'd defend it against prompt injection, tool misuse, or data exfiltration, or attack a provided model/agent with adversarial inputs and build a detector for the exploit. The most advanced track, and the one that maps most directly to what CrowdStrike is building with AgentWorks. Realistic scope for 8 hours: one clear exploit or defense, demoed live rather than a fully hardened system.
> 1st $800 · 2nd $200 · 3rd Prize Box

### Ciocca Venture Award (separate award, official text)
> The Ciocca Venture Award, presented in partnership with SCU's Ciocca Center for Innovation and Entrepreneurship, recognizes the team whose AI-powered cyber defense solution shows the strongest potential to become a real product or venture. Teams are judged on the clarity of the problem they're solving, who would use and pay for their solution, how it stands apart from existing tools, and a credible path from prototype to launch, alongside a working demo.
> 1st $1000 · 2nd $500 · 3rd Prize Box

### Official judging criteria, as used for scoring
- **Track 3** (from the brief): (1) fits the brief: build-and-defend against prompt injection / tool misuse / data
  exfiltration, *or* attack a provided agent + build a detector; (2) one **clear** exploit or defense; (3) **demoed live**;
  (4) realistic scope, "rather than a fully hardened system"; (5) relevance to what CrowdStrike is building with AgentWorks.
- **Ciocca** (from the award text): clarity of the problem · who would use and pay · how it stands apart from existing
  tools · credible path from prototype to launch · alongside a working demo.

### How we map to the brief (honest)
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
- **Not in the brief:** DVAA's 22 CTF challenges. The brief does not mention them, so we don't pitch them as a goal.
- **Ciocca:** no extra build. If the team targets it (#128, default YES), the deck adds one venture slide covering
  problem, who uses and pays, differentiation vs Falcon AIDR / NeMo Guardrails / Lakera, and path to launch.
  Open: is a separate submission/form needed, and can one project win both?

---

## 1. The decision (locked)

**Path B: attack the provided vulnerable agent (DVAA) + build a detector for the exploit.**

Track 3 offers two paths (see the verbatim brief in §0): (A) build an agent and defend it, or (B) attack a provided agent and build a detector. **We pick B** as the main demo (Path A is covered by the OpsBot add-on in `track3a/`) because:
1. The target (DVAA — Damn Vulnerable AI Agent) is **handed to us**; we spend all 8h on the detector, which is what's judged.
2. A **real exploit landing live** is more visceral than "here's how I'd defend."
3. It maps **1:1 to the product CrowdStrike just shipped** (Falcon AIDR / AgentWorks guardrails) — the biggest scoring lever. See §2.
4. DVAA hands us **ground-truth labels, a defended A/B twin, and a baseline detector to beat** (§5) — rare gifts for an 8-hour build.

## 2. The core insight — mirror a product CrowdStrike *just* shipped

If our project is an inline prompt-injection / exfil detector in front of an agent, we are demoing a **miniature Falcon AIDR**. The judges are CrowdStrike people — they will see their own roadmap reflected back.

- **Sep 16 2025** — **Charlotte AI AgentWorks** (no-code agent builder + **guardrails**) announced at Fal.Con 2025.
- **Sep 16 2025** — Pangea acquisition announced (closed Sep 26; price *reported* by press at ~$260M — CrowdStrike's 10-Q shows ~$223M consideration + ~$46.5M vesting stock) → **Falcon AI Detection & Response (AIDR)**: real-time prompt-injection + jailbreak detection, **"up to 99% efficacy at sub-30ms latency"** (Pangea release; internal benchmark).
- **Dec 15 2025** — **Falcon AIDR GA**, "powered by … 180+ known prompt injection techniques" (GA release). NVIDIA NeMo Guardrails integration followed in **Mar 2026**.
- Kurtz: **"Each prompt becomes an entry point for the adversary."** Sentonas: **"Prompt injection is a frontier security problem."** GA release: **"prompts are the new malware."**

**Say their words on stage:** "AI Detection and Response," "guardrail," "prompts are the new malware," "detect → alert → block in real time."

## 3. The product — one sentence

> *"We turn an indirect prompt injection into a CrowdStrike-style detection — a real AIDR-shaped alert, mapped to MITRE ATLAS and OWASP, rendered as a Falcon incident graph — and it fires the instant the agent tries to exfiltrate data, at the tool boundary, even when the attack evades the baseline scanner."*

An inline, tool-boundary **detection-and-response guardrail** for AI agents — a working slice of Falcon AIDR.

## 4. The target — DVAA facts that shape the build

- **Stack:** pure Node.js (ESM, **Node ≥24**), raw `http` servers, vanilla-JS dashboard. Apache-2.0, by OpenA2A.
- **Run (fully OFFLINE — no API key needed; agents fall back to deterministic canned responses):**
  - Docker: `docker run -p 127.0.0.1:9000:9000 -p 127.0.0.1:7001-7021:7001-7021 opena2a/dvaa:0.9.2` → open `http://localhost:9000`.
  - Source: `npm install && npm start`. (BYOK OpenAI/Anthropic key optional, set in dashboard Settings; **no Ollama path**.)
- **Dashboard :9000.** Agents on **7001–7023**. Key ones: **SecureBot 7001** (hardened), **LegacyBot 7003** (fully broken), **RAGBot 7005** ↔ **RAGBot-AIM 7014** (A/B), **FlightBot 7017** ↔ **-AIM 7018**, **RepoBot 7022** ↔ **7023**.
- **Hook point:** every agent exposes **OpenAI-compatible `/v1/chat/completions`** → our detector is a **reverse proxy**, protocol-agnostic, works on all agents, sees request + response.
- **Live surfaces to tap:** `GET /api/attack-log` on :9000 (ring buffer: `categories, successful, input, response, port`), `GET /stats`, `GET /health`. Each **agent reply carries a `dvaa{}` block = GROUND TRUTH** (`exfilAttempted/exfilExecuted/exfilTargetUrl/toolCalls`) → score our detector's precision/recall against it.
- **Baseline to beat:** their `detectAttacks()` in `src/core/vulnerabilities.js` only scans **head+tail 8KB** of long inputs → an **evadable gap** we demonstrate beating.
- **Built-in secure contrast:** **AIM** (`src/aim-enforcer.js`) is a capability-grant guard at the tool-call boundary; AIM-paired twins run identical code with enforcement ON = an instant "vulnerable vs defended" A/B.
- **Pitch gold:** scenario READMEs repeatedly state *"Automated static detection not yet implemented in HMA for this scenario"* (indirect injection, exfil) — the organizers' own scanner has gaps **exactly where a runtime detector fills.**

## 5. The detector — architecture (by impact/effort)

**Primary stack: reverse-proxy guardrail with tool-boundary taint + honeytoken tripwire + egress heuristics.** No GPU, ms latency, deterministic. Buildable in 2–3h.

1. **Honeytoken tripwire (build FIRST — live-demo insurance).** DVAA already plants fake secrets (`SENSITIVE_DATA`: fake API keys, DB/admin creds, SSNs). Detector fires the instant one of those exact tokens crosses an egress boundary in a tool call / response. **100% deterministic → guaranteed to fire on stage.**
2. **Taint / data-provenance.** Tag content from untrusted-content tools (RAG doc, web fetch, repo `AGENTS.md`) as tainted; flag when tainted data flows into a sensitive sink (`http:post`, `send_email`, `submit_to_index`). Shows *why* it's exfil (data flow) — the "lethal trifecta" made concrete, and it catches the exfil **before AIM does**, at the same seam.
3. **Egress heuristics.** Regex/entropy on egress args + responses: secrets (`sk-…`, `AKIA…`, `-----BEGIN`), PII (email/SSN/CC), markdown-image/URL exfil (EchoLeak CVE-2025-32711 pattern), new/non-allowlisted domains. **Scan the FULL input** (beats their 8KB head/tail gap).
4. **(If time) Meta Prompt Guard 2 (22M)** as a fast ML injection classifier on inbound text — adds a published-accuracy number and "we score every input in <50ms."

**Detector design guardrail (our own rules):** bounded + **fail-loud** — if inbound text exceeds a cap, alert/reject, never silently truncate (a detector that drops oversized input is itself the vuln — and is *exactly* DVAA's 8KB baseline bug). Verify on **data-rich** inputs, not toy ones.

## 6. The output — make it look like Falcon/AIDR

Each detection = an **AIDR/Falcon-shaped alert JSON**: `DetectName`, `Severity`/`SeverityName`, `Tactic`/`Technique` (MITRE **ATLAS** + ATT&CK — Exfiltration T1041/T1567), entities (agent-session / tool-call IDs), `PatternDispositionDescription` (block/allow), timestamp, state. Tag each live with **OWASP LLM01/LLM02/LLM06**, **Agentic ASI01/ASI02**, **OASB-1** category. *(ATLAS matters most to this crowd — include it.)*

**Centerpiece: a Falcon-style AI Incident Graph** — render the tool-call chain (read tainted RAG doc → read customer/cred DB → `http:post`) as a CrowdStrike-style process-tree / incident timeline, malicious node highlighted, **taint path glowing red source→sink.** ~2–3h over the event log.

## 7. The demo arc (< 3 min, rehearsed, deterministic)

| Time | Beat |
|---|---|
| 0:00–0:20 | **Problem.** "Air Canada lost a tribunal case over its chatbot. Chevy's bot agreed to sell a Tahoe for $1. Every prompt is an entry point for the adversary." |
| 0:20–0:35 | **Solution.** "We built [Name] — an inline AI detection-and-response guardrail for agents. A mini Falcon AIDR." |
| 0:35–1:15 | **EXPLOIT (live, RAGBot 7005 / RepoBot 7022).** Poisoned RAG doc / repo `AGENTS.md` hijacks the agent → it exfiltrates admin creds + SSNs via `submit_to_index`/`http:post`. Secret leaves on screen. Show it **evading DVAA's own 8KB scanner.** Pause — let it land. |
| 1:15–2:05 | **DETECT → ALERT → BLOCK.** Same attack through our proxy. Honeytoken tripwire fires; incident graph lights up; taint path glows red; tool call BLOCKED. Show latency + **precision/recall vs the `dvaa{}` ground truth.** |
| 2:05–2:35 | **How it works.** One slide: tool-boundary taint + egress inspection = "prompts, responses, agent actions," the AIDR model. |
| 2:35–3:00 | **Outcome + close.** "X/Y attacks caught at <N ms, including the 2/2 cases that evade the baseline scanner's 8KB window (the baseline has the higher prevention recall, at a 12.8% benign FP rate; see `sentinel/scoring/RESULTS.md`). Same attack hits the AIM-defended twin and SecureBot — secure by design. This is a working slice of Falcon AIDR." |

## 8. Live-demo failure modes to avoid

- **No live cold LLM/API calls in the 3-min window** — DVAA runs offline with canned responses; capture the event log and **replay deterministically.** Live path = optional encore.
- **Don't key the detector on one exact injection string** — anchor on the deterministic honeytoken, but also show 2–3 **pre-computed** variants (AgentDojo/InjecAgent) so it reads as real detection.
- **Don't run the mutating attacker live** — record / replay the winning variant.
- **Don't live-scan the 2.66M-row AIT dataset** — pre-index a tiny slice (the exact data-scale stall trap).
- Pre-seed data-rich state; keep a recorded full-demo video as fallback.

## 9. Scoring levers, ranked

1. Demo maps 1:1 onto Falcon AIDR / AgentWorks (speak their words) — the brief itself says Track 3 "maps most directly to what CrowdStrike is building with AgentWorks". (The old "workflow integration" criterion came from the superseded AgentWorks-rules proxy.)
2. One crisp exploit → detect → block arc, end-to-end, live.
3. The visual "aha": red (pwned) vs green (saved), side by side; taint path glowing.
4. Quantified outcome: **real precision/recall vs ground truth** + latency (mirror "99% @ sub-30ms"); "we catch the 2/2 cases that evade the baseline's 8KB window" — never an unqualified "we beat the baseline": DVAA's baseline has the higher prevention recall, at a 12.8% benign FP rate (see `sentinel/scoring/RESULTS.md`).
5. SOC credibility: AIDR-shaped alerts + MITRE ATLAS + OWASP mapping + incident graph.
6. Relatable hook (refund bot / Air Canada / Chevy) = stakes land instantly.

## 10. Team work-split (8h)

- **A — Attack bench:** drive DVAA's RAGBot/RepoBot/LegacyBot exploit paths (`dvaa demo aim-ab -i`, `dvaa demo repo -i`, curl on 7003), capture event logs, build the 2–3 pre-computed evasion variants. *(Stretch: thin refund-bot re-skin for relatability.)*
- **B — Detector core:** reverse proxy → honeytoken tripwire → taint tracking → egress heuristics → AIDR alert JSON + MITRE/OWASP mapping; scoring harness vs `dvaa{}` ground truth. **Main 8h focus.**
- **C — Dashboard + incident graph:** split-screen attack/defense, incident graph, trust-score gauge; record the demo video.
- **Shared, last 90 min:** freeze features, seed state, **rehearse the 3-min script 3×**, cut anything not in the arc.

## 11. What NOT to build

- Not a full hardened system (slide: one clear exploit/defense).
- Not NeMo Guardrails config, full CaMeL, or general taint analysis — cite as credibility slides, don't build.
- No fifth feature at hour 6. Freeze and rehearse.

See `RESEARCH.md` for the evidence base and citations; `NEXT_PROMPT.md` to scaffold the project.
