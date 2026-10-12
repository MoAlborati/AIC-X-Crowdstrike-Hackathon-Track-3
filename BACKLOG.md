# BACKLOG — SentinelProxy (Track 3, DVAA defense)

Ordered tickets. **One ticket = one branch = one PR.** The orchestrator picks the top ticket whose
deps are merged; disjoint file scopes may run in parallel (see LOOP.md §Parallelism). Each child agent
runs the relevant `gates/` checklist and ends with `STATUS: DONE | DEGRADED | BLOCKED`.

Legend: **DoD** = Definition-of-Done item in GOAL.md it serves. **Scope** = file paths this ticket may
touch (parallelism key — no two in-flight tickets may overlap).

---

## T1 — Verify DVAA + capture exploit transcripts
- **DoD:** 1
- **Deps:** none
- **Scope:** `captures/`, `scripts/`
- **What:** Confirm DVAA runs fully OFFLINE (deterministic canned responses, no API key) on the build
  machine. Capture 3–5 exploit transcripts (request + response, incl. the per-reply `dvaa{}`
  ground-truth block) exfiltrating a planted honeytoken. Recommended headline agent pairs to capture:
  **RAGBot 7005 ↔ RAGBot-AIM 7014**, **RepoBot 7022 ↔ 7023**, **LegacyBot 7003**.
- **Acceptance:**
  - DVAA brought up offline; `GET /health` on each target port OK; ports/commands recorded in `scripts/`.
  - ≥3 transcripts saved to `captures/` as structured JSON, each including the full request, full
    response, and the raw `dvaa{}` block (`exfilAttempted/exfilExecuted/exfilTargetUrl/toolCalls`).
  - At least one transcript shows a planted secret crossing an egress boundary (ground-truth positive).
  - A short `captures/README.md` indexes each capture (agent, port, scenario, expected label).
- **Gate notes:** delivery-gate — captures come from the **real DVAA fleet**, not hand-written toy JSON.

## T2 — Proxy skeleton
- **DoD:** 2 (foundation)
- **Deps:** T1
- **Scope:** `sentinel/proxy/`, `sentinel/config/`
- **What:** Reverse proxy forwarding `POST /v1/chat/completions` to a configured DVAA target port.
  Logs request + response (full body), exposes a block path (reject with an alert instead of forwarding),
  config file for target port + mode (observe | block).
- **Acceptance:**
  - Proxy forwards to a live DVAA agent and returns its response unchanged in observe mode.
  - Full request + response bodies are logged (not head/tail-truncated) to a capture sink.
  - Block mode short-circuits a flagged request and returns a structured refusal (hook for T3/T4).
  - Config selects target port + mode without code edits.
- **Gate notes:** tester-gate — exercise against a **real** DVAA port (real seam), payloads >8KB logged
  in full; se-gate — document the request-size bound + its fail-loud behavior.

## T3 — Detector core
- **DoD:** 2
- **Deps:** T2
- **Scope:** `sentinel/detectors/`
- **What:** Detection pipeline, in build order: (1) **honeytoken tripwire** (exact planted-secret match
  crossing an egress sink — deterministic, demo insurance); (2) **taint / provenance** (tag
  untrusted-content tool outputs; flag tainted data flowing into a sensitive sink); (3) **egress
  heuristics** (secret/PII regex + entropy, markdown-image/URL exfil, non-allowlisted domains).
  Scans the **full payload** (beats DVAA's head+tail 8KB baseline). **Bounded + fail-loud**: if input
  exceeds the configured cap, raise/alert — never silently truncate.
- **Acceptance:**
  - Honeytoken tripwire fires deterministically on a captured positive from T1.
  - Taint rule flags untrusted-read → sensitive-read → external-send in one turn.
  - Full-payload scan catches a payload that hides the signal beyond the first/last 8KB.
  - Oversize input triggers a loud ALERT/raise with `{payload_size, cap, action}` logged — no silent
    truncation (firm rule: bounded + fail-loud).
  - Detector returns a verdict object consumable by T4.
- **Gate notes:** tester-gate — payloads >8KB **and** multi-hundred-row tool outputs; delete-the-fix
  proof (≥3 RED pre-fix, GREEN post-fix) for any bug; se-gate — every cap documented with its failure mode.

## T4 — Alert schema + mapping
- **DoD:** 3
- **Deps:** none (parallel-safe — pure schema/mapping on a verdict shape agreed with T3)
- **Scope:** `sentinel/alerts/`
- **What:** Falcon/AIDR-shaped alert JSON (`DetectName`, `Severity`/`SeverityName`, `Tactic`/`Technique`,
  entities, `PatternDispositionDescription`, timestamp, state). Mapping table tagging each detection with
  **MITRE ATLAS + ATT&CK** (Exfiltration T1041/T1567), **OWASP LLM01/02/06**, **Agentic ASI01/ASI02**,
  **OASB-1**.
- **Acceptance:**
  - A sample verdict renders a valid AIDR-shaped alert JSON (schema documented).
  - Each detector rule maps to its ATLAS/ATT&CK + OWASP + ASI + OASB tags via a single mapping table.
  - Mapping is data-driven (table/config), not hard-coded per call site.
- **Gate notes:** se-gate — schema versioned; reviewer-gate — tags cite the frameworks in RESEARCH.md.

## T5 — Dashboard
- **DoD:** 4
- **Deps:** T4
- **Scope:** `sentinel/dashboard/`
- **What:** Split-screen **attacker | detector** view. Falcon-style **incident graph** rendering the
  tool-call chain with the **taint path source→sink glowing red**; latency number; **trust-score gauge**;
  **alert feed**; replay from `captures/` (no live LLM calls on stage).
- **Acceptance:**
  - Loads a capture from `captures/` and replays it deterministically.
  - Incident graph highlights the malicious node and glowing taint path.
  - Latency and trust-score render; alert feed lists AIDR alerts from T4.
  - Handles a data-rich capture (multi-hundred-row tool output) without stalling or truncating the graph.
- **Gate notes:** delivery-gate — replay runs on real captures; tester-gate — data-rich capture, latency
  measured and displayed.

## T6 — Attack corpus
- **DoD:** 1
- **Deps:** T1
- **Scope:** `captures/variants/`
- **What:** Evasion variants of the captured exploits, including **one that evades DVAA's 8KB baseline**
  (signal placed outside head/tail). Plus a **pre-computed** exfiltration subset drawn from
  AgentDojo / InjecAgent (recorded, not run live). All defensive test fixtures for the detector/scoring.
- **Acceptance:**
  - ≥1 variant demonstrably passes DVAA's 8KB baseline yet carries the exfil signal.
  - A pre-computed AgentDojo/InjecAgent exfil subset saved as labeled fixtures in `captures/variants/`.
  - Each variant labeled with expected ground truth for T7 scoring.
- **Gate notes:** tester-gate — fixtures are data-rich and labeled; delivery-gate — variants replayable.

## T7 — Scoring harness
- **DoD:** 5
- **Deps:** T3, T6
- **Scope:** `sentinel/scoring/`
- **What:** Replay captures (T1) + variants (T6) through the detector (T3) and compare verdicts against
  the `dvaa{}` ground-truth labels. Output precision / recall / median latency table.
- **Acceptance:**
  - Produces a table: precision, recall, median + p95 latency across the corpus.
  - Compares detector verdict vs `dvaa{}` label per case; false pos / false neg itemized.
  - Runs headless and deterministically from `captures/`.
- **Gate notes:** tester-gate — real seams (real detector, not a mock), full corpus incl. >8KB cases;
  delivery-gate — latency numbers reproduced on a clean run.

## T8 — Secure-by-design contrast
- **DoD:** 6
- **Deps:** T1, T3
- **Scope:** `captures/contrast/`, `sentinel/scoring/` (read-only reuse)
- **What:** Run the same attack against the **AIM-defended twin** (e.g. RAGBot-AIM 7014) and **SecureBot
  7001**; capture that the attack fails there. Show the A/B (vulnerable vs defended) alongside our detector.
- **Acceptance:**
  - Captured transcripts from an AIM twin + SecureBot where the same exploit is refused/blocked
    (ground-truth negative on exfil execution).
  - A/B comparison documented: vulnerable agent (pwned) vs defended twin (safe) vs our proxy (detects+blocks).
- **Gate notes:** delivery-gate — contrast captured from the real fleet.

## T9 — Demo
- **DoD:** 7
- **Deps:** all (T1–T8)
- **Scope:** `demo/`
- **What:** `demo/SCRIPT.md` (<3-min beat sheet from STRATEGY §7), `demo/run-demo.sh` (deterministic
  replay), fallback-video checklist, and **3 rehearsals logged**.
- **Acceptance:**
  - `run-demo.sh` drives the full exploit → detect → block → alert → graph → scoring arc from captures.
  - SCRIPT.md matches the STRATEGY §7 beats and times under 3 minutes.
  - ≥3 rehearsals logged (time + what broke/fixed); fallback video checklist present.
- **Gate notes:** delivery-gate (hackathon-scaled convergence) — **≥5 consecutive clean demo replays**
  before we call it demo-ready (see `gates/delivery-gate.md`).

---

## Stretch (only after all 7 DoD items merge — do not start early)
- **S1** Meta Prompt Guard 2 sidecar — fast ML injection classifier on inbound text; adds a published
  accuracy number. Scope: `sentinel/detectors/promptguard/`.
- **S2** Refund-bot costume — relatable re-skin of one scenario (Air Canada / Chevy hook). Scope: `demo/`.
- **S3** AIT alert-feed slice — render detections as a SOC feed using a tiny pre-indexed AIT slice.
  Scope: `sentinel/dashboard/ait/`.
- **S4** Drop-in guardrail one-liner — closing-slide "add one line, get the proxy" packaging. Scope: `sentinel/proxy/`.

---

## Dependency graph

```
T1 ──┬─> T2 ──> T3 ──┬─> T7
     │              │
     ├─> T6 ────────┘
     ├─> T8   (also needs T3)
     └────────────────────────────────> T9 (needs all)
T4 (independent) ──> T5
T3, T4 ──> (feed T5 alert feed / T9)
```

## Parallel waves

- **Wave 1 (no deps):** T1, T4.
- **Wave 2 (after T1; T4 done or parallel):** T2, T6, T5 — disjoint scopes (`proxy/`, `captures/variants/`,
  `dashboard/`).
- **Wave 3 (after T2):** T3 (`detectors/`) — can run alongside T5/T6.
- **Wave 4 (after T3 + T6):** T7; (after T1 + T3) T8 — disjoint scopes (`scoring/`, `captures/contrast/`).
- **Wave 5 (after all):** T9 (`demo/`), then Stretch.

> Parallelism cap: at most 3 implementer agents at once, only on disjoint scopes (LOOP.md §Parallelism).
