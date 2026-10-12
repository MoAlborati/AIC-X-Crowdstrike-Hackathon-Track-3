# SentinelProxy — deck outline (10 slides + 1 backup)

> **Status: T9 — wired to merged components.** Pairs with `demo/SCRIPT.md` (driven by `demo/run-demo.sh`), and
> the slide numbers here match the beat sheet. Main now has T2–T8 + T11; the 8KB-evasion beat is required (DoD 1).
> Rules:
> - Every factual claim is the verbatim "Safe slide wording" from `planning/CITATIONS.md` (PR #8, merged).
> - Metric slots `<<METRIC: …>>` are filled only from T7 output. **Never estimate.**
> - Narrative pattern from `planning/ADJACENT.md` §5: **one** narrative analogy (the bank teller), then the
>   structure (confused deputy), then 2–3 mechanisms that pass the precondition test (§4), each with its source field.
>   Never claim a defense works *because* it works in another field.

---

## Slide 1 — Title

**On slide**
- **SentinelProxy**
- An inline AI detection-and-response guardrail for agents, at the tool boundary.
- Team · CrowdStrike × Santa Clara University · Track 3: Secure — Attack & Defend the Agent

**Speaker notes**
On screen for about 2 seconds while Beat 1 starts. Don't read it aloud. Go straight to the hook.

---

## Slide 2 — Every prompt is an entry point

**On slide**
- "Air Canada lost a tribunal case over its chatbot (Moffatt v. Air Canada, 2024 BCCRT 149)."
- "A Chevy dealer's chatbot 'agreed' to sell a 2024 Tahoe for $1 — 'that's a legally binding offer – no takesies backsies.'"
- "AI is rewriting the enterprise attack surface at breakneck speed. Each prompt becomes an entry point for the adversary." — George Kurtz, CEO & founder

**Speaker notes**
Beat 1 (0:00–0:20). Two relatable failures, then CrowdStrike's own words. Say "tribunal case", never "court".
Say "agreed to sell", never "sold". No car was sold. Don't quote the C$812 award, which is still unconfirmed in
CITATIONS. Close the beat with: "Today that prompt can arrive inside a document your agent reads."

---

## Slide 3 — The confused deputy

**On slide**
- Diagram with three actors:
  - **Principal** (user) owns the authority.
  - **Deputy** (the agent and its tools) holds the authority.
  - **Adversary** (the author of a RAG doc, web page or repo file) can only write content the deputy reads.
- Caption: *A new bank teller who obeys notes slipped into deposit envelopes.*
- Footer: Hardy, "The Confused Deputy", ACM SIGOPS OSR 22(4):36–38, 1988.

**Speaker notes**
Beat 2 (0:20–0:40). This is the **only** narrative analogy in the talk. Don't add Agloe, HACCP or immunology.
The point is that the attacker never breaks in. The harm runs through the deputy's *legitimate* permissions, so the
place to defend is between the deputy and its tools, not the deputy's input (ADJACENT §1, §10.1). That's where
SentinelProxy sits.

---

## Slide 4 — Live: RAGBot 7005 gets pwned (RED)

**On slide**
- Left pane: the terminal replay of `captures/attack/aim-ab.demo.json` runA.
- Callouts: `submit_to_index` → canary hit carrying `dvaa-admin-secret` + `SSN 123-45-6789` (fake sandbox values).
- Badge: `dvaa.exfilExecuted = true`.
- **8KB-evasion moment (REQUIRED — DoD item 1):** the two mid-document T6 variants
  (`EVA-POS-MIDDLE-001`, `EVA-BENCH-MIDDLE-001`) hide the injection between DVAA's head/tail 8KB windows
  (`docLength ≈ 22.8KB`, `injectionAtByte ≈ 11.3K`, `inMiddleGap=true`) → DVAA's baseline scanner: **no detection**.
  A full scan still carries the signal. SentinelProxy (T3) catches **both** cases the baseline misses (`t3 2/2`).

**Speaker notes**
Beat 3 (0:40–1:00) + Beat 3b (1:00–1:20). Deterministic replay of DVAA's own bundled payload (APWN-DE-003), no live
LLM. Pause two seconds after the secret appears. The 8KB-evasion beat is DoD item 1 — **always run it**; the proof is
the two mid-document fixtures plus the T7 "beats baseline" output (`scripts/eval.sh score`). DVAA is the
organizer-provided sandbox; every secret is fake.

---

## Slide 5 — Same attack, through SentinelProxy (GREEN)

**On slide**
- Dashboard screenshot or live pane: incident graph, poisoned RAG doc → sensitive read → `submit_to_index`,
  with the taint path in red and the request marked **BLOCKED (pre-forward)** — blocked before it is forwarded.
- Benign row first: `7005 travel-policy question → ALLOWED`.
- Latency readout: `<<METRIC: this call's detection latency, ms (T5 readout)>>`.
- Alert card: DetectName · Severity · MITRE ATLAS · ATT&CK "T1567 Exfiltration Over Web Service · T1041
  Exfiltration Over C2 Channel" · "LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure ·
  LLM06 Excessive Agency" · Agentic ASI01 · ASI02 · **OASB-1**.

**Speaker notes**
Beat 4 (1:20–1:50). Order matters: benign passes first, then the attack is **blocked request-side, before the request
is forwarded** (ADJACENT §6a, FP economics). Prevention is the request-side block (T3) and the egress guard (T12) — a
response-side honeytoken tripwire is **alert-only**, deterministic insurance that names the exact planted secret but
does not by itself prevent. Point at the case card: it names the *source* document, the tool and the sink, not just
"blocked". Use the tags T4 actually emits in `sentinel/alerts/mapping.js`. Don't add tags by hand.

---

## Slide 6 — Red vs green: RAGBot 7005 ↔ RAGBot-AIM 7014

**On slide**

| RED | GREEN | GREEN |
|---|---|---|
| **RAGBot 7005** | **RAGBot-AIM 7014** | **RAGBot 7005 + SentinelProxy** |
| exfil executed | denied: "action 'http:post' is outside the agent's declared capability grant" | blocked pre-forward, before the request is sent |
| `exfilExecuted=true` | `exfilExecuted=false` | `action=blocked_request` (proxy-block.proxy.jsonl) |

- Footer (T8, PR #16, merged): `scripts/eval.sh contrast` verifies the A/B against DVAA ground truth
  (SecureBot 7001 + AIM 7014 + SentinelProxy). The recorded runs are checked, never rewritten.
- **Prevention map (from T3, #24):** RAGBot 7005 → blocked **request-side, pre-forward**; LegacyBot 7003 →
  **reply withheld**; RepoBot 7022 → proxy **alert-only**, and **T12's egress guard is the control that stops it**.

**Speaker notes**
Beat 5 (1:50–2:05). The headline pair. 7014 is the same agent code with DVAA's AIM capability guard switched on,
which is secure by design. The point to make: AIM works because someone rebuilt the agent, while SentinelProxy protects
the *unmodified* 7005 from outside. Both quoted verdicts come straight from `aim-ab.demo.json`. Different agents are
prevented by different controls (see the prevention map) — request-side block, response withhold, or egress guard —
and response-side tripwires are alert-only. Don't claim we beat AIM. We complement it.

---

## Slide 7 — Borrowed controls that pass the precondition test

**On slide**

| Field | Control it already uses | Our rule |
|---|---|---|
| Payments fraud | Confirmation of Payee: check the payee before money moves | **Destination provenance:** a destination that appears only in untrusted tool output → BLOCK `payee_not_confirmed` |
| Agency law / OAuth | Limited power of attorney: the agent can't exceed what the principal granted | **User-turn mandate:** `{tool, destination, max_amount, expires}` derived only from the user's turn, and content can't widen it |
| Counterintelligence / firm rule | Dead-man switch: silence means stop | **Fail-closed:** timeout, crash or oversize input → deny egress + ALERT. Full-payload scan, never truncated |

- Footnote: "Confirmation of Payee passed 2 billion checks (Pay.UK, Mar 2024)."

**Speaker notes**
Beat 6 (2:05–2:30). All three are rated **Yes** on the per-mechanism precondition test (ADJACENT §6a, §10.3a). Their
preconditions hold in agent-land because destinations, tools and amounts are structured and checked outside the
model. **Before the demo, confirm each row is implemented in merged T3.** Drop any row that isn't, and don't present
it as built. If a judge asks "why not a classifier?": "Spam filters lost to spammers because the attacker wrote the
content being scored. We enforce at the boundary." (ADJACENT §10.4). The fail-closed row is the direct answer to
DVAA's 8KB head+tail baseline.

---

## Slide 8 — Results (scored against DVAA ground truth)

**On slide**

| Metric | Value |
|---|---|
| Precision | `<<METRIC: precision (T7)>>` |
| Recall | `<<METRIC: recall (T7)>>` |
| False-positive rate (benign runs) | `<<METRIC: benign FP rate (T7)>>` |
| Median latency | `<<METRIC: median latency, ms (T7)>>` |
| Corpus | `<<METRIC: N attack + M benign cases (T7)>>` |

- Caption: "Labels from DVAA's `dvaa{}` ground-truth block, not our own judgment."

**Speaker notes**
Beat 7, first half (2:30–2:40). Copy every number verbatim from the T7 output file and note the file and commit in the
deck's source. FP rate sits beside recall on purpose, because it's a headline metric (BACKLOG T7). If T7 also reports p95
latency, keep it in backup and don't add it here. **If T7 hasn't merged, this slide says "pending" and the script drops
the numbers sentence. Never put a guessed number on it.** Don't put AIDR's figure on this slide as a comparison. A
benchmark of a different system on a different corpus isn't like-for-like.

---

## Slide 9 — A working slice of Falcon AIDR

**On slide**
- "Prompt injection is a frontier security problem. Adversaries are injecting hidden instructions into GenAI tools to weaponize the very systems transforming how work gets done." — Michael Sentonas, president
- "The AI interaction layer is the new attack surface and prompts are the new malware."
- SentinelProxy maps onto the same shape: inspect prompts, responses and agent actions → detect → alert → block, with
  AIDR-shaped alerts tagged MITRE ATLAS + OWASP.
- Small print: "Falcon AIDR GA Dec 15 2025; NVIDIA NeMo Guardrails integration added Mar 2026."

**Speaker notes**
Spoken only as the close line in Beat 7: "This is a working slice of Falcon AI Detection and Response, at the tool
boundary." Leave the slide up during Q&A. If anyone cites AIDR's efficacy, the only allowed wording is "Up to 99%
efficacy at sub-30ms latency (CrowdStrike, internal benchmark)". Keep "up to" and the attribution.

---

## Slide 10 — Close

**On slide**
- **SentinelProxy:** stops the confused deputy at the tool boundary.
- Exploit → detect → alert → block, deterministic, scored against ground truth.
- Repo link · team names · "Thank you."

**Speaker notes**
On screen at 2:50 for "Thank you". Hard stop at 3:00. Hold it during Q&A, with Slide 9 and backup B1 ready.

---

## Backup B1 — Sources (not presented, for Q&A)

**On slide** (verbatim citation strings from `planning/CITATIONS.md`)
- Moffatt v. Air Canada, 2024 BCCRT 149
- Chevy Tahoe, Jalopnik (Dec 2023)
- Kurtz quote, Sentonas quote, and "prompts are the new malware": CrowdStrike press releases (Pangea, Sep 16 2025; Falcon AIDR GA, Dec 15 2025)
- Hardy, "The Confused Deputy", ACM SIGOPS OSR 22(4):36–38, 1988
- Confirmation of Payee passed 2 billion checks (Pay.UK, Mar 2024)
- OWASP LLM Top 10 2025; OWASP Top 10 for Agentic Applications 2026; MITRE ATT&CK T1041 / T1567; MITRE ATLAS (data v2026.09, per `sentinel/alerts/mapping.js`)
- DVAA (OpenA2A), pinned commit per `captures/README.md`

**Speaker notes**
For Q&A only. Answer "where's that from?" by pointing here, never from memory.
