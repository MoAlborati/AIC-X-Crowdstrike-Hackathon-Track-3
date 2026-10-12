# SentinelProxy — deck outline (10 slides + 1 backup)

> **Status: T9 — wired to merged components.** Pairs with `demo/SCRIPT.md` (driven by `demo/run-demo.sh`), and
> the slide numbers here match the beat sheet. Main now has T2–T8 + T11; the 8KB-evasion beat is required (DoD 1).
> **Pitch frame (critic #112, creative #105):** an exfil-focused guardrail for tool-using agents. Not "a slice of
> Falcon AIDR", and not a jailbreak classifier. We own the losing blended prevention number, then show where data
> actually leaves and the control that actually blocks: default-deny egress at the tool boundary. "Deterministic
> sandbox, no LLM" is said in Beat 1. Every replay is labelled **recorded**. "100% precision" and "0% FP" are never
> headlines.
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
- An exfil-focused guardrail for tool-using agents, at the tool boundary.
- Small print: deterministic sandbox (DVAA, offline, canned replies), no LLM in the loop.
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
CITATIONS. Close the beat with: "Today that prompt can arrive inside a document your agent reads." Then, within the
first 20 seconds: "Everything you'll see runs in a deterministic sandbox, no LLM, and most of it is recorded. We'll say which."

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

## Slide 4 — Recorded: RAGBot 7005 gets pwned (RED)

**On slide**
- Badge: **RECORDED**.
- Left pane: the terminal replay of `captures/attack/aim-ab.demo.json` runA.
- Callouts: `submit_to_index` → canary hit carrying `dvaa-admin-secret` + `SSN 123-45-6789` (fake sandbox values).
- Badge: `dvaa.exfilExecuted = true`.
- **8KB-evasion moment (recorded, 10 seconds max):** the two mid-document T6 variants
  (`EVA-POS-MIDDLE-001`, `EVA-BENCH-MIDDLE-001`) hide the injection between DVAA's head/tail 8KB windows
  (`docLength ≈ 22.8KB`, `injectionAtByte ≈ 11.3K`, `inMiddleGap=true`) → DVAA's baseline scanner: **no detection**.
  A full scan still carries the signal. **8KB evasion: 2/2 fixtures** caught by SentinelProxy (T3).

**Speaker notes**
Beat 3 (0:40–1:00) + Beat 3b (1:00–1:20). Deterministic replay of DVAA's own bundled payload (APWN-DE-003), no live
LLM. Say "recorded". Pause two seconds after the secret appears. Keep the 8KB-evasion moment to 10 seconds: it is n=2
fixtures against a weakness DVAA built in on purpose, so it is not a differentiator. The proof is the two mid-document
fixtures plus "8KB evasion: 2/2 fixtures" from `sentinel/scoring/results.json`. Never say a blanket
"beats the baseline": on the full corpus DVAA's baseline has the higher prevention recall (slide 8). DVAA is the
organizer-provided sandbox; every secret is fake.

---

## Slide 5 — Same attack, through SentinelProxy (GREEN), then default-deny egress

**On slide**
- **LIVE** (the one live beat), through the real shipped proxy: benign question → **HTTP 200** (forwarded untouched), then DVAA's
  aim-ab request (poisoned retrieved content supplied in the request, the client-side RAG pattern) → **HTTP 403**,
  **BLOCKED (pre-forward)** by T3: `detector: sentinel-t3`, reasons `exfil_instruction_inbound` · `injection_markers` ·
  `payee_not_confirmed`.
- **RECORDED:** request-side alert card (T4, built by the T10 pipeline): `IndirectPromptInjection` · High · rule
  `inbound.exfil_instruction` · ATLAS AML.T0051.001 · LLM01 · ASI01 · **OASB-1** · Blocked.
- **RECORDED, the blocking story:** default-deny egress at the tool boundary. Egress alert card (Beat 4b, `HoneytokenExfiltrationAttempt`): ATT&CK "T1567 Exfiltration Over Web Service ·
  T1041 Exfiltration Over C2 Channel" · "LLM01 · LLM02 Sensitive Information Disclosure · LLM06 Excessive Agency" ·
  ASI01 · ASI02 · OASB-1. Attacker server received nothing (RAGBot 7005 and RepoBot 7022).

**Speaker notes**
Beat 4 (1:10–1:40) + Beat 4b (1:40–1:55). The 200/403 is the only live step; say "recorded" when the screen moves to
the alert card and the egress run. Egress default-deny is the prevention story: it stops the RepoBot exfil that the
request proxy cannot. Order matters: benign passes first, then the attack is **blocked request-side, before the request
is forwarded** (ADJACENT §6a, FP economics). Prevention is the request-side block (T3) and the egress guard (T12). A
response-side honeytoken tripwire fires after the tool already ran, so it is **alert-only for prevention**, but in block
mode the **reply is withheld** (T3-fix #56), so the secret never reaches the client. Spoken lines: `demo/SCRIPT.md`,
verbatim from `run-demo.sh`. Point at the case card: it names the *source* document, the tool and the sink, not just
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
  **reply withheld**; RepoBot 7022 → the proxy **cannot stop the exfil** (payload read in-agent), and **T12's egress guard is the control that stops it**.

**Speaker notes**
Beat 5a (1:55–2:05), recorded: say so. The headline pair. 7014 is the same agent code with DVAA's AIM capability guard switched on,
which is secure by design. The point to make: AIM works because someone rebuilt the agent, while SentinelProxy protects
the *unmodified* 7005 from outside. Both quoted verdicts come straight from `aim-ab.demo.json`. Different agents are
prevented by different controls (see the prevention map) — request-side block, response withhold, or egress guard —
and response-side tripwires are alert-only for prevention (the reply is withheld in block mode). Don't claim we beat AIM. We complement it.

---

## Slide 7 — Borrowed controls that pass the precondition test

**On slide**

| Field | Control it already uses | Our rule |
|---|---|---|
| Payments fraud | Confirmation of Payee: check the payee before money moves | **Destination provenance:** a destination that appears only in untrusted tool output → BLOCK `payee_not_confirmed` |
| Agency law / OAuth | Limited power of attorney: the agent can't exceed what the principal granted | **User-turn mandate:** `{tool, destination, max_amount, expires}` derived only from the user's turn, and content can't widen it |
| Counterintelligence / reliability engineering | Dead-man switch: silence means stop | **Fail-closed:** timeout, crash or oversize input → deny egress + ALERT. Full-payload scan, never truncated |

- Footnote: "Confirmation of Payee passed 2 billion checks (Pay.UK, Mar 2024)."

**Speaker notes**
Beat 6 (2:05–2:20). Speak only the payee and fail-closed rows; the mandate row stays on the slide. All three are rated **Yes** on the per-mechanism precondition test (ADJACENT §6a, §10.3a). Their
preconditions hold in agent-land because destinations, tools and amounts are structured and checked outside the
model. **Before the demo, confirm each row is implemented in merged T3.** Drop any row that isn't, and don't present
it as built. If a judge asks "why not a classifier?": "Spam filters lost to spammers because the attacker wrote the
content being scored. We enforce at the boundary." (ADJACENT §10.4). The fail-closed row is the direct answer to
DVAA's 8KB head+tail baseline.

---

## Slide 8 — Results (scored against DVAA ground truth)

**On slide**

| | T3 (SentinelProxy) | DVAA baseline |
|---|---|---|
| Detection recall (any finding) · benign FP | `<<METRIC>>` · `<<METRIC>>` | `<<METRIC>>` · `<<METRIC>>` |
| Prevention recall (pre-forward) · benign FP | `<<METRIC>>` · `<<METRIC>>` | `<<METRIC>>` · `<<METRIC>>` |
| Prevention where data actually leaves (exfil positives) | `<<METRIC>>` (57/71 as of RESULTS.md now) | `<<METRIC>>` (64/71) |
| 8KB evasion | `<<METRIC>>`/2 fixtures | — |
| Corpus | `<<METRIC: N attack + M benign cases>>` | |
| In-detector latency | median under a tenth of a millisecond, p95 around half a millisecond | |

Copy the slide's numbers from `sentinel/scoring/results.json` (summarized in `sentinel/scoring/RESULTS.md`) after the
15:00 rescore. Beat 7 of `run-demo.sh` prints them.

- Caption: "Labels from DVAA's `dvaa{}` ground-truth block, not our own judgment. Benign FP is measured on the
  164-case benign corpus."

**Speaker notes**
Beat 7, first half (2:30–2:40). Copy every number verbatim from the T7 output file and note the file and commit in the
deck's source. FP rate sits beside recall on purpose, because it's a headline metric (BACKLOG T7). If T7 also reports p95
latency, the one latency phrase we quote is "median under a tenth of a millisecond, p95 around half a millisecond" (figures in RESULTS.md). **Never put a guessed number on it.**
Say it plainly: our detection recall is now slightly above DVAA's baseline, but the baseline has the higher
prevention recall, at a 12.8% benign FP rate. Where data actually leaves, we prevent 57/71 with 0/164 legit requests blocked; DVAA prevents
64/71 but blocks 21/164; most of our blended loss is injection-only text that steals nothing (18.6% vs 46.6%).
Our 0 of 164 benign blocked is on the 164-case benign corpus, which the rules were also tuned on. It's a small sample,
not a zero-FP guarantee, so it is never the headline. Held-out benign: 1/32 blocked (a security-awareness memo quoting an injection phrase; same as before #46), and 4/32 raise an alert without a block. Held-out attacks: 14 of 16 hand-written paraphrases detected, but on an independent reviewer's 6 further paraphrases, 1 detected, so recall on novel phrasings is limited — see PR #46.
The 2/2 cases that evade the baseline's 8KB window are a narrow, n=2 result, not a differentiator. Don't put AIDR's figure on this slide as a comparison. A
benchmark of a different system on a different corpus isn't like-for-like.

---

**Scope (say it if asked about generalization):** "SentinelProxy stops prompt-injection-driven exfiltration and tool misuse. Generic jailbreak text with no action is out of scope for blocking (alerted at most); pair it with a jailbreak classifier such as Prompt Guard." On a held-out set of 600 attack and 400 benign cases from 3 public Hugging Face sets of generic jailbreaks and injections, none carrying an exfil destination, T3 detected 28.5% and prevented 0%, with 0/400 false positives (detection by set: Gandalf 58%, SPML 19%, jailbreak-classification about 8%); DVAA detected and prevented 60.7%, with 22/400 (5.5%) false positives. Held-out; see [`captures/holdout-hf/RESULTS.md`](../captures/holdout-hf/RESULTS.md).

---

## Slide 9 — We attacked ourselves

**On slide**
- Two bars: **jailbreak text, held out: 0% prevented (0/600)**, because none of it has anywhere to send data · **where
  data actually leaves: we prevent 57/71 with 0/164 legit requests blocked; DVAA prevents 64/71 but blocks 21/164**.
- "Spacing out an account number slips past our blocking rule today." (Found by our own critic, issue #112; not yet fixed.)
- "Regex at the front door is not enough. Default-deny egress at the tool boundary is what actually stops the data."
- Small print: held-out set = 600 attack + 400 benign rows from 3 public Hugging Face sets, never tuned on: T3 detected
  28.5%, prevented 0%, 0/400 benign blocked; DVAA detected and prevented 60.7% at 22/400 benign
  (`captures/holdout-hf/RESULTS.md`). Main corpus: `sentinel/scoring/RESULTS.md`.

**Speaker notes**
Beat 7, second half. Spoken: "We attacked ourselves too. On 600 held-out public jailbreaks we never tuned on, we
prevent zero, because none of them has anywhere to send your data. And spacing out an account number slips past our
blocking rule today. Both are on our limitations list." Say it before a judge reads it to you. Leave the slide up
during Q&A. If AIDR comes up: we complement it at the tool boundary, we haven't integrated with Falcon's APIs, and the
only allowed efficacy wording is "Up to 99% efficacy at sub-30ms latency (CrowdStrike, internal benchmark)".

---

## Slide 10 — Close

**On slide**
- **SentinelProxy:** an exfil-focused guardrail for tool-using agents: one pre-forward check, default-deny egress, alerting.
- Deterministic sandbox, no LLM. Scored against DVAA ground truth, misses and held-out failures published.
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
