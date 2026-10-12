# ADJACENT — what other fields already know about our problem

> Operator prompt: *"explore the adjacent knowledge angle… consider what makes knowledge adjacent, is it
> transferable based on the actor"*.
>
> Sources: eight parallel research reports (T0b), covering analogical-transfer theory plus seven domains:
> software injection, BEC / social engineering, counterintelligence, fraud / AML, safety engineering /
> aviation, HACCP / food safety, and immunology. This file follows the theory report's framing. The
> mechanism catalog (§6) feeds the T3/T4/T5/T7 acceptance criteria and the stretch tickets in BACKLOG.md.
> **Round 2 (T0c, §10)** adds eight more domains and an empirical revision of the transfer framing (§10.1).

---

## 1. What makes knowledge adjacent

Knowledge from another field is **adjacent** when its **relational structure** matches ours. Shared
vocabulary or a similar look doesn't count (Gentner's systematicity principle [T1]). An analogy holds
up when a connected system of relations maps across, such as "X causes Y, which enables Z," with
one-to-one role mapping and the **same goal** (Holyoak & Thagard [T3]).

Our structure is the **confused deputy** (Hardy 1988 [T2]), which has three actors:

| Role | In SentinelProxy / DVAA |
|---|---|
| **Principal** owns the authority | the user / operator |
| **Deputy** holds the authority and acts on it | the LLM agent and its tools |
| **Adversary** cannot act directly | the author of the injected content (web page, email, RAG doc, repo file) |

The adversary's **only lever** is content the deputy has to consume to do its job, and in that content
data and control are mixed together. The harm happens through the deputy's **legitimate** permissions.
This is the principal-agent problem with a third party who manipulates the agent's *information*
instead of its *incentives*.

**Is knowledge transferable based on the actor?** Mostly not. Round 2's empirical study (§10.1) found that
matching actor roles is **neither necessary nor sufficient** for a transfer to work:
- **Comparable choke point (D4)** and **adversary adaptivity relative to the feedback available (D5 vs D7)**
  are the best predictors of whether a defense *survives* contact with a prompt injector who reads our detector.
- **Actor triad + shared channel** mainly tell us *where the choke point should sit* (between the deputy and its
  tools) and whether the field's threat model applies.

So the actor structure locates the choke point but doesn't predict success. Whether a given defense transfers is
answered per mechanism (§4).

## 2. Scoring rubric (0 = absent, 1 = partial, 2 = full)

| # | Dimension | Test question |
|---|---|---|
| D1 | Actor triad | Is there an owner, an empowered intermediary, and an outsider who can't act directly? |
| D2 | Shared channel | Is the adversary's *only* lever content the deputy must read, with data and control mixed together? |
| D3 | Borrowed authority | Is harm done through the deputy's *legitimate* permissions rather than by breaking in? |
| D4 | Choke point | Does every harmful action pass through one point you can inspect? |
| D5 | Adaptive adversary | Does the threat watch your defenses and adapt? (A natural hazard scores 0.) |
| D6 | FP economics | Are base rates and false-positive tolerance close to ours (rare attacks, low tolerance for friction)? |
| D7 | Ground-truth feedback | Do you eventually learn which cases were attacks, so you can tune? |
| D8 | Out-of-band channel | Is there a trusted side channel (callback, second signer, asking the user)? |

**Filter rule.** A field needs **D1 + D2 ≥ 3** to supply *threat models*. A field below that can still
supply *engineering patterns*, but only where **D4 + D7 ≥ 3**.

## 3. Ranking of the 7 domains

| Rank | Domain | D1–D8 | Total | Supplies | Main driver |
|---|---|---|---|---|---|
| 1 | Software injection (SQLi/XSS) | 1,2,2,2,2,2,2,0 | 13 | threat model + mechanisms | D2: the same data/control channel collapse. Parameterization corresponds to CaMeL-style plan/data separation. |
| 2 | BEC / social engineering | 2,2,2,1,2,1,1,2 | 13 | threat model + mechanisms | D1 + D8: a human deputy steered through email, defended by callback verification. |
| 3 | Counterintelligence / deception | 2,2,2,0,2,1,0,1 | 10 | threat model + concepts | D1/D2: a handler steering an insider through information. No choke point and little feedback, so it yields concepts more than mechanisms (canaries are the exception). |
| 4 | Fraud / AML / payments | 1,1,2,2,2,2,1,1 | 12 | mechanisms (choke point) | D4/D6: a choke point and similar FP economics. The triad is weaker because the adversary is often the customer. |
| 5 | Safety engineering / aviation | 1,0,1,2,0,1,2,2 | 9 | engineering patterns only | D4/D7: checklists, barriers, near-miss reporting. Its hazards mostly don't adapt. |
| 6 | HACCP / food safety | 0,1,0,2,0,1,2,0 | 6 | engineering patterns only | D4 only: the critical-control-point concept. Fails D5. |
| 7 | Immunology | 0,1,1,1,1,1,1,0 | 6 | narrative only | Adaptation is co-evolutionary but there is no principal. Fails both filter gates, so it is mostly metaphor. |

Counterintelligence ranks above AML despite the lower total, because the D1/D2 gate comes first and
AML's triad is weaker. **Treat totals as a guide, not as the rank.** Totals measure *relevance*. To predict
whether a mechanism will survive, weight D4 and D5-vs-D7 (§10.1).

## 4. Per-mechanism precondition test

Score the **mechanism**, not the domain. List the preconditions the mechanism needs, then check each
one in agent-land. Worked examples from the theory report:

- **PASS: BEC callback verification.** It needs a rare, high-stakes action, an out-of-band channel the
  adversary can't control, and a reachable principal. All three hold. Our version is human
  confirmation **through the dashboard, not the chat**, for egress to a new destination.
- **FAIL: immunological self/non-self.** It needs foreign material to carry a stable marker that
  differs from self. Injected text *is* natural language, the same substance as legitimate content, and
  an adaptive adversary imitates "self" on purpose. Nothing about it is a marker.
- **PARTIAL: AML transaction monitoring.** It needs a choke point (holds: tool call ≈ transaction),
  risk-scored thresholds (partly holds), and ground truth (partly: slow and sparse). It also needs
  population baselines across millions of accounts, which does **not** hold: agent sessions are short
  and different each time. Adopt **velocity and destination-novelty rules**, and **not** learned
  behavioral baselines.

The last column of the catalog (§6) applies this test to every mechanism.

## 5. Narrative vs mechanism adjacency

- **Narrative adjacency:** the audience already knows the story. Examples are HACCP ("check at every
  critical control point"), the bank teller who calls you back, the sentinel clinic, and Agloe, the
  trap town. Use one in the **first 30 seconds** to make the choke-point idea feel obvious.
- **Mechanism adjacency:** the same structure, which is what **justifies the design**. SQL injection →
  prompt injection is "the same bug, 25 years later." BEC callback maps to out-of-band confirmation.
  Confirmation of Payee maps to destination provenance.

**Pitch pattern:** open with a narrative analogy, name the structure (confused deputy), then show 2–3
mechanisms that pass the precondition test, each with its source field. **Never claim a defense works
*because* it works in immunology** (or in baking).

---

## 6. Mechanism catalog

"Preconditions hold?" applies §4: **Yes** = all hold in agent-land, **Partial** = it works only in the
reduced form described, **No** = excluded. Ticket placement uses BACKLOG.md IDs. S5–S9 are the new
stretch tickets.

### 6a. Convergent deterministic core (folded into T3/T4/T5/T7)

| Source domain(s) | Mechanism | Our feature | Ticket | Preconditions hold? |
|---|---|---|---|---|
| Fraud (Confirmation of Payee, new-payee hold); BEC (payment-change rule); software injection (CSP origin allowlist) | Verify the payee / destination before anything settles | **Destination provenance:** extract recipients, URL hosts and webhooks from tool args. A destination that is not named in the *user's* turn and not on the allowlist, and that appears only in tool-returned (untrusted) text → BLOCK `payee_not_confirmed` | T3 | **Yes.** Destinations are structured and extractable, the check runs outside the model, and provenance comes from the tool/source, not the content. |
| Software injection (Perl taint mode, source→sink pairs); CI (Meta Agents Rule of Two); immunology (danger theory); aviation (interlock / lethal trifecta); HACCP (allergen cross-contact) | Tainted data may not reach a sensitive sink | **Source→sink flow rule:** tag every tool result `{source, trust}`. Session flags are A = untrusted input, B = sensitive read, C = egress/state change. A+B then C → block or escalate. A tainted substring (≥8-char shingle / n-gram) copied into sink args is a high-confidence hit | T3 | **Partial.** Turn-level taint holds. Byte-precise taint does not, because the model rewrites text. Present it as session-level information-flow control. |
| CI (canary trap / barium meal, mountweazels, honeytokens); HACCP (lot codes) | Plant unique, never-legitimately-used markers and watch the exit | **Per-session canaries + seeded fake records:** `mintCanary(session, tool)` produces realistic per-session secrets, plus 3–5 "Agloe" records seeded into readable data. The egress scan also checks base64, hex and URL-decoded forms. Any hit names the session, the tool that fetched it, and the sink | T3 | **Partial.** Holds for detection. Weak spots: legitimate summaries can leak them (the "Agloe problem", so block vs alert is set per sink), and encode/split/paraphrase evades literal matching. The registry needs a TTL/LRU bound and must fail loud. |
| CI (dead-man switch); firm rule (no silent degradation) | If the watchdog goes quiet, the action fires | **Fail-closed:** scanner timeout, crash, oversize input or a full registry → deny egress and raise ALERT. Never pass traffic silently | T3 | **Yes.** Purely an engineering property of the proxy. |
| HACCP (CCP + critical limit + pre-decided corrective action); aviation (envelope protection, STPA unsafe-control-action table); software injection (CSP report-only → enforce) | Declarative per-control-point limits that no prompt can argue past | **Per-tool policy with report-only / enforce modes:** `policy.json` per tool (allowlist, path jail, byte cap, banned tools, pre-declared action `block` / `quarantine` / `require_human`). Rolled out in `report-only` (log + `/report`), then flipped to `enforce`. Pure function, no LLM | T3 (maps onto T2's observe/block config) | **Yes** for hard limits (destinations, paths, bytes, call order). **No** for semantic intent, which has no envelope. |
| Fraud (velocity limits, anti-structuring); aviation (token-bucket rate limit) | Cumulative and near-threshold caps, not just single-call caps | **Cumulative caps:** a session ledger keyed `session+tool` covering count, summed amount/bytes, and N calls each just under the single-call cap → HOLD + alert | T3 | **Yes.** Deterministic. The ledger itself is bounded (firm rule) and overflow raises. |
| Fraud (SAR narrative, link analysis); HACCP (one-up/one-down lot trace); immunology (contact tracing) | Every case gets a who/what/when/where/why story and a trace | **Narrative case card on alerts:** one paragraph, e.g. "Instruction originated in `ticket#4411` body → influenced `send_email(to=attacker@x)` → blocked by `payee_not_confirmed`", plus the provenance edges for the graph | T4 (field), T5 (render) | **Yes.** Attribution points at the tainted *source*, not just the session (CI caveat). |
| Immunology (autoimmunity / peripheral tolerance); fraud (FP economics); aviation (approval fatigue) | False-positive budget is a first-class metric | **FP rate on benign runs as a headline metric**, shown next to detection rate | T7 (also T9 demo: one benign pass + one attack block) | **Yes.** Our FP tolerance is *lower* than a bank's, because nobody triages a demo. |

### 6b. Heavier ideas (stretch tickets)

| Source domain(s) | Mechanism | Our feature | Ticket | Preconditions hold? |
|---|---|---|---|---|
| BEC (callback verification); fraud (maker-checker, step-up, cooling-off hold); CI / aviation (two-person integrity) | A second, independent channel confirms high-risk actions | **Approval queue:** `PENDING_APPROVAL` for egress/write after taint. Dashboard approve/deny showing tool, args, **taint source** and risk. Auto-deny on timeout. Optional delay-then-release hold for irreversible tools | S5 | **Yes** for a human approver through the UI. **Partial** for an LLM judge, which must never see the untrusted context. Approval fatigue means gating only sinks after taint. |
| Immunology (quarantine); aviation (circuit breaker / fuse) | Degrade the session safely instead of killing it | **Quarantine / circuit breaker:** CLOSED → OPEN after N detections, → HALF_OPEN for read-only tools. Egress returns "held for review". One-click reset | S6 | **Partial.** Attackers can trip it deliberately (DoS), so it needs per-source scoping and a clear reset path. |
| BEC (new-hire probation, least privilege); software injection (object-capability / POLA) | Authority shrinks once untrusted content is in play | **Capability downgrade after taint:** CLEAN → TAINTED state machine, tool manifest annotated `read`/`write`/`egress`, TAINTED sessions limited to read tools or routed to S5 | S7 | **Yes.** Simplest form of CaMeL-style information-flow control. Costs usefulness. |
| BEC ("does this match the request?"); software injection (task-scoped tool manifests) | The action must fit the task the principal asked for | **Intent-alignment check:** a deterministic task-verb → allowed-tools map built from the *trusted* user turn only, plus an optional context-stripped LLM judge | S8 | **Partial.** The deterministic map holds. The judge is not foolproof. |
| HACCP (tamper-evident seal); software injection (SPF/DKIM provenance) | Changes to trusted config are visible | **Tool-manifest integrity:** HMAC the tool definitions and system prompt at startup and verify on every call. A mid-session change (MCP "rug pull") → alert | S9 | **Yes** for detection. It is a *detection* control, so don't claim it "blocks". |

### 6c. Defense-in-depth only (keep inside existing T3 heuristics, never the sole gate)

| Source domain(s) | Mechanism | Note | Preconditions hold? |
|---|---|---|---|
| HACCP (metal detector); BEC (secret scanning) | Egress DLP: key regexes, entropy, base64 in query strings, markdown-image URLs | Already in T3 "egress heuristics" | **Yes** as a tripwire |
| BEC (Cialdini red flags); immunology (innate layer) | Urgency/authority/secrecy lexicon score on untrusted text | It may *raise risk* only. Paraphrase evades it | **Partial** |
| Software injection (output encoding); BEC (external banner) | Spotlighting: randomized `<<UNTRUSTED id=nonce>>` delimiters | Advisory to the model, not a control | **Partial** |
| Aviation (Swiss cheese) | Layered pipeline with per-layer score + reason | Keep ≥1 layer deterministic, since layers that are all LLMs fail together | **Yes** |
| Aviation (ASRS near-miss) | JSONL near-miss feed of every block/flag | Value is logging and analysis only | **Yes** |

### 6d. Explicitly excluded

| Source domain(s) | Mechanism | Why excluded |
|---|---|---|
| Fraud (behavioral profile / anomaly score); HACCP (SPC control charts); immunology (Forrest n-gram "self", thymic training) | **Learned behavioral baselines** | **They need history we won't have.** Banks train on millions of labelled transactions. We will have a handful of benign runs, so these become noise or are easy to game, and a poisoned warm-up run learns the attack as "self". Agent tool sequences are open-ended. **Not built, not a stretch ticket.** |
| Immunology (vaccination / signature memory) | SimHash memory of past payloads | An adaptive attacker reads our detector, so this is easy to evade. At most it is a T6 fixture idea. |
| Software injection (Dual-LLM / CaMeL quarantine wrapper) | Full plan/data separation | The correct long-term answer, but a large build that changes DVAA's agent, not our proxy. Cite it in the pitch as the direction secure-by-design is heading (T8 contrast). |

---

## 7. Pitch lines

Narrative opener (pick one), then the structure, then the mechanisms (§5 pattern):

- **Software injection (mechanism):** "In 1998 we tried to stop SQL injection by filtering for bad quotes.
  We lost for a decade, until parameterized queries kept code and data apart. AI agents are at their 1998
  now. SentinelProxy doesn't try to out-guess the model. It tracks where every byte came from and
  enforces what it's allowed to reach."
- **BEC:** "Your agent just fell for a BEC scam, the $3 billion-a-year fraud. It never felt suspicious, so
  it never picked up the phone. SentinelProxy is the phone call."
- **Fraud:** "Banks stopped asking *'is this really the customer?'*, because the customer is usually
  real and being scammed. They ask *'does this payment make sense?'* Every tool call is a transaction,
  and we score it before it settles." Short version: **"Confirmation of Payee for AI agents."**
- **Counterintelligence (Agloe):** "In the 1930s two mapmakers invented a town called Agloe… if Agloe showed
  up on someone else's map, that map was copied. We plant Agloes in your agent's world: fake keys, fake
  customers, fake files. A legitimate agent never needs them. The moment one heads for the exit, we know
  who took it, through which tool, and we stop it at the door." (The twist, where a real store got
  built at Agloe, is our honest point about false positives.)
- **Aviation:** "Fly-by-wire for agents: the pilot can be fooled, but the envelope can't."
- **Theory (bank teller):** "A new bank teller who obeys notes slipped into deposit envelopes." Then name
  the confused deputy.
- **HACCP / immunology (narrative only):** "A bakery doesn't trust its flour; it proves it safe at every
  critical control point." / "A sentinel site doesn't treat every patient; it notices the first unusual
  cluster. Like the immune system, it reacts to *danger*: secrets moving toward the exit." Map each term
  once, then switch to security language.

## 8. What doesn't transfer (consolidated)

- **Escaping / sanitizing / a "kill step."** No escape character makes text inert to an LLM, and nothing
  makes untrusted text safe to obey. Segregate it instead. Regex and lexicon detection is a
  **tripwire, not a boundary** (software injection, HACCP, BEC).
- **Precise taint propagation.** The model rewrites, summarizes and translates, so we can only say the
  context was tainted, not which bytes were (software injection).
- **Static limits against an adaptive adversary.** Salmonella doesn't paraphrase; injectors do
  (HACCP, immunology, aviation: physics vs semantics).
- **Learned baselines and self-models.** These need history and a deterministic "self" (fraud, HACCP
  SPC, immunology). See §6d.
- **Sampling.** One injected call is enough to cause harm, so every call is checked (HACCP).
- **Training and awareness, gut feel, fear of consequences.** Each session starts from zero, so controls
  sit outside the model (BEC).
- **Sender identity.** Injected text inside a trusted doc has no authenticated sender, so provenance
  comes from the tool/source (BEC).
- **Out-of-band step-up when the prompt *is* the channel.** Step-up goes to a real human or to a model
  that never sees the untrusted text (fraud, CI two-person integrity).
- **Approval fatigue** is worse for agents because of call volume, so gate only sinks after taint
  (fraud, BEC, aviation).
- **Recall, reimbursement, beacons and seals come after the harm.** Exfiltration can't be reversed, so
  present these as *prevention plus damage scoping*, never recovery (fraud, HACCP, CI).
- **Independence of layers.** Swiss cheese fails if every layer is an LLM classifier (aviation).
- **Circuit breakers** can be tripped deliberately for DoS (aviation).
- **Canary discoverability and evasion.** Fixed-format canaries get skipped by the injection itself,
  and encoding or splitting beats literal match (CI).
- **Cooperative protocols** (TCAS, sterile cockpit, ASRS blame-free reporting) assume cooperating
  parties, so they are metaphors at most (aviation).
- **The FP economics trap.** Banks tolerate high FP rates because analysts triage them. A demo that
  blocks benign tasks loses the judges (fraud, immunology).

---

## 9. Citations

**⚠ = the source report flagged this as unverified or written from memory. Check it before it goes on
a slide.**

**Theory** (the whole report was written from memory ⚠)
- [T1] ⚠ Gentner (1983), Structure-mapping. *Cognitive Science* 7(2). https://doi.org/10.1207/s15516709cog0702_3
- [T2] ⚠ Hardy (1988), The Confused Deputy. *ACM SIGOPS OSR* 22(4). https://dl.acm.org/doi/10.1145/54289.871709 (also https://cap-lore.com/CapTheory/ConfusedDeputy.html)
- [T3] ⚠ Holyoak & Thagard (1989), Analogical mapping by constraint satisfaction. *Cognitive Science* 13(3). https://doi.org/10.1207/s15516709cog1303_1
- [T4] ⚠ Fu, Moreno, Yang, Wood (2014), Bio-inspired design / design-by-analogy. *J. Mech. Des.* 136(11). https://doi.org/10.1115/1.4028289
- [T5] ⚠ Greshake et al. (2023), indirect prompt injection. https://arxiv.org/abs/2302.12173
- [T6] ⚠ Debenedetti et al. (2025), CaMeL. https://arxiv.org/abs/2503.18813; Beurer-Kellner et al. (2025), Design Patterns. https://arxiv.org/abs/2506.08837

**Software injection** (no URLs fetched in that run ⚠)
- ⚠ Greshake et al. 2023: https://arxiv.org/abs/2302.12173
- ⚠ Debenedetti et al. 2025, CaMeL: https://arxiv.org/abs/2503.18813
- ⚠ Willison, Dual LLM pattern: https://simonwillison.net/2023/Apr/25/dual-llm-pattern/; lethal trifecta: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- ⚠ Beurer-Kellner et al. 2025: https://arxiv.org/abs/2506.08837
- ⚠ perlsec (taint mode): https://perldoc.perl.org/perlsec
- ⚠ MDN CSP-Report-Only: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
- ⚠ Rain Forest Puppy, Phrack 54 (1998): http://phrack.org/issues/54/8.html

**BEC / social engineering**
- FBI IC3 2024 report: BEC $2.77B, 21,442 complaints. https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf (summary: https://www.nacha.org/news/fbis-ic3-finds-almost-85-billion-lost-business-email-compromise-last-three-years)
- ⚠ FBI IC3 2025: BEC $3.046B, 24,768 complaints, wire/ACH in 86%, >$30M AI-linked. Verified only through a secondary summary: https://www.mcdonaldhopkins.com/insights/news/the-sobering-truth-of-the-fbis-2025-internet-crime-complaint-center-report. **The "$3 billion" pitch line depends on this. Check the primary IC3 report.**
- Hines et al. 2024, Spotlighting: https://arxiv.org/abs/2403.14720
- ⚠ Rimasauskas fake-invoice scheme (~$100M+ from Google/Facebook), DOJ: https://www.justice.gov/usao-sdny/pr/lithuanian-man-sentenced-5-years-prison-theft-over-120-million-fraudulent-business
- ⚠ Arup $25M deepfake (BEC report, from memory; see also the fraud report's Fortune link below)
- EchoLeak CVE-2025-32711: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711

**Counterintelligence / deception**
- Meta AI, Agents Rule of Two: https://ai.meta.com/blog/practical-ai-agent-security/
- Willison on the Rule of Two: https://simonw.substack.com/p/new-prompt-injection-papers-agents
- Agloe, NY: https://en.wikipedia.org/wiki/Agloe,_New_York
- Thinkst Canarytokens: https://canarytokens.org, https://github.com/thinkst/canarytokens
- ⚠ Spitzner (2003), "Honeytokens: The Other Honeypot", SecurityFocus (no live URL verified)
- Fictitious entry: https://en.wikipedia.org/wiki/Fictitious_entry
- Canary trap: https://en.wikipedia.org/wiki/Canary_trap

**Fraud / AML / payments**
- PSR APP-fraud reimbursement (Oct 2024), via FinanceMagnates: https://www.financemagnates.com/fintech/payments/tackling-app-scams-the-uks-bold-steps-to-protect-consumers-from-fraud/
- PSR, Confirmation of Payee expanded: https://psr.org.uk/news-and-updates/latest-news/news/anti-fraud-tool-confirmation-of-payee-expanded-to-hundreds-of-more-firms
- Pay.UK, CoP passes 2 billion checks: https://www.wearepay.uk/confirmation-of-payee-reaches-two-billion-checks-helping-protect-uk-consumers-against-fraud/
- FFIEC 2021 authentication guidance (Sidley summary): https://www.sidley.com/en/insights/newsupdates/2021/08/ffiec-guidance-on-authentication-and-access-to-financial-institution-services-and-systems
- Arup $25.6M deepfake, 15 transfers (Fortune): https://fortune.com/europe/2024/05/17/arup-deepfake-fraud-scam-victim-hong-kong-25-million-cfo
- ⚠ FinCEN SAR narrative guidance: https://www.fincen.gov/sites/default/files/shared/sarnarrcompletguidfinal_112003.pdf

**Safety engineering / aviation** (whole report from memory ⚠)
- ⚠ Reason (2000), Human error: models and management. *BMJ* 320:768. https://www.bmj.com/content/320/7237/768
- ⚠ Leveson & Thomas, STPA Handbook (2018): https://psas.scripts.mit.edu/home/get_file.php?name=STPA_handbook.pdf
- ⚠ SKYbrary, Flight Envelope Protection: https://skybrary.aero/articles/flight-envelope-protection
- ⚠ NASA ASRS: https://asrs.arc.nasa.gov/
- ⚠ Fowler, CircuitBreaker: https://martinfowler.com/bliki/CircuitBreaker.html
- ⚠ OSHA Lockout/Tagout, 29 CFR 1910.147: https://www.osha.gov/control-hazardous-energy
- ⚠ Willison, lethal trifecta (2025): https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/

**HACCP / food safety**
- FDA, HACCP Principles & Application Guidelines (NACMCF 1997): https://www.fda.gov/food/hazard-analysis-critical-control-point-haccp/haccp-principles-application-guidelines
- USDA FSIS, Seven Principles: https://www.fsis.usda.gov/sites/default/files/media_file/2020-08/5-Seven-Principles.pdf
- FDA FSMA 204 Food Traceability Rule: https://www.fda.gov/food/food-safety-modernization-act-fsma/fsma-proposed-rule-food-traceability
- Peanut Corporation of America recall (2009): https://www.mprnews.org/story/2009/02/10/cracking-the-case-of-the-poison-processed-peanuts
- 1982 Tylenol poisonings: https://www.history.com/articles/extra-strength-tylenol-poisonings-1982

**Immunology** (no web searches run ⚠; the report says the PDF, arXiv IDs and DOI are stable but the CDC path has moved before)
- ⚠ Forrest, Hofmeyr, Somayaji, Longstaff (1996), A Sense of Self for Unix Processes. https://www.cs.unm.edu/~immsec/publications/ieee-sp-96-unix.pdf
- ⚠ Matzinger (2002), The Danger Model. *Science* 296. https://doi.org/10.1126/science.1071059
- ⚠ Aickelin & Cayzer (2002), Danger Theory and AIS. https://arxiv.org/abs/0801.3549
- ⚠ Greensmith, Aickelin, Cayzer (2005), Dendritic Cells. https://arxiv.org/abs/0910.3117
- ⚠ CDC ILINet sentinel providers (path may have moved): https://www.cdc.gov/fluview/overview/index.html

---

## 10. Round 2 (T0c)

> Sources: nine more parallel research reports. Eight are domain reports: algorithmic trading, voice
> assistants, medication safety, military order authentication, software supply chain, OAuth / delegated
> authorization, agency law and newsroom source verification. The ninth is an empirical study of past
> cross-domain transfers, and it **revises** the round-1 framing (§10.1, reflected in §1). Most round-2 reports
> stopped early after a cost hook fired, so several were written from memory. Their unverified flags are kept in §10.7.

### 10.1 Empirical revision: what actually predicts transfer

The transfer-cases report looked at eight historical borrowings: aviation checklists → surgery, artificial
immune systems → IDS, epidemic models → worms, Bayesian filtering → spam, crypto → email (PGP vs
DKIM/DMARC), andon → CI gates, fraud scoring → ATO detection, and HACCP → food/software. Findings:

- **Matching actor roles is neither necessary nor sufficient.** It is not necessary, because epidemic models and
  HACCP transferred with no principal/deputy/adversary match. It is not sufficient, because spam filtering
  matched the roles exactly (the adversary acts only through content) and still eroded once spammers adapted.
- **The best predictors are (a) a comparable choke point (D4), and (b) how fast the adversary adapts (D5)
  relative to the ground-truth feedback available (D7).** Choke-point enforcement survived (DKIM/DMARC, CI
  merge gates). Defenses that relied on vigilance decayed (PGP, the mandated checklists in Ontario). Content scoring held only
  while labels kept arriving faster than the attacker adapted (ATO fraud scoring held; naive-Bayes spam and AIS-IDS did not).
- **Actor roles mainly tell you *where the choke point should sit*.** In a confused-deputy setup it goes
  between the deputy and its tools, not on the deputy's input.

**What this changes for us**
1. The rubric totals in §3 and §10.2 measure *relevance*. They do not predict that a defense will survive.
   Rank mechanisms by **D4**, and by **D5 vs D7**: where adaptation outruns feedback, use only structural
   checks (provenance, flow, capability scope) and never content scoring as the gate.
2. Prompt-injection classifiers have the same structure as spam filters, so they stay **secondary signals**
   (this already matched §6c; it is now backed by evidence).
3. We can't get fast labels in a hackathon, so every proxy decision is logged with its outcome (T7, plus
   override-rate tracking in §10.3) to build what feedback we can.
4. Name the assumption about the adversary that would break each borrowed mechanism (the epidemic-model lesson).

### 10.2 Rubric scores (8 new domains)

Same D1–D8 rubric as §2. **Caveat:** these domains were *picked* because their triad matched, so D1–D3 are
uniformly 2 and the totals cluster at 13–15. Per §10.1, read the **D4** and **D5/D7** columns.

| Domain | D1–D8 | Total | D4 choke point | D5 vs D7 (adapt vs feedback) | Supplies |
|---|---|---|---|---|---|
| Newsroom source verification | 2,2,2,2,2,2,1,2 | 15 | publish decision | adaptive (2) > feedback (1): structural checks only | provenance grading, corroboration, callback, ablation test |
| Voice assistants (Alexa / Google Home) | 2,2,2,2,2,1,1,2 | 14 | wake-word + purchase gate | adaptive (2) > feedback (1): signature blocking lost in hours | consequence tiers, out-of-band PIN, cross-session simultaneity |
| Medication safety (Rx, CPOE, BCMA) | 2,2,2,2,1,2,1,2 | 14 | pharmacy verify + bedside scan | mostly non-adaptive error | hard/soft stops, scan-vs-order, override-rate evidence |
| Military / emergency order authentication | 2,2,2,2,1,2,1,2 | 14 | launch console / alert-origination software | mostly accidents | chain of command, challenge-reply, ROE manifest, two-key |
| Software supply chain | 2,2,2,2,2,1,1,2 | 14 | install/resolve time, registry | adaptive (2) > feedback (1): xz was found by accident | lockfile pinning, capability diff, name-shadowing |
| Algorithmic trading (SEC 15c3-5) | 2,2,2,2,1,1,2,1 | 13 | pre-trade risk gate | feedback (2) ≥ adaptation (1): best D7 in round 2 | typed per-tool limits, throttles, kill switch |
| OAuth / delegated authorization | 2,1,2,2,1,2,1,2 | 13¹ | token endpoint + resource-server validation | protocol attacks don't change much | per-call grants (RAR), audience binding, narrowing exchange |
| Agency law | 2,2,2,1,1,2,1,2 | 13 | weak (loss assigned after the fact) | slow on both | mandate (limited POA), apparent vs actual authority, ratification, liability framing |

¹ The OAuth report states "14/16", but its per-dimension scores add up to 13. This table uses the per-dimension scores.

**Round-2 convergence.** Five of the eight domains independently arrived at the same control. A **principal-signed,
pre-declared mandate** that content cannot widen: OAuth RAR (RFC 9396), the limited power of attorney,
rules of engagement, the BCMA scan against the order, and 15c3-5 pre-set limits. The other strong
convergence is **callback on an independently sourced channel**: pharmacist, newsroom, agency law
(payee change), voice PIN and military challenge-reply. It extends round-1 BEC callback and §6b S5.
Both fit §10.1 because they are structural checks at the choke point and not content scoring.

### 10.3 Mechanism catalog (round 2)

Same columns as §6. Ticket IDs are BACKLOG.md IDs. S10–S12 are new stretch tickets.

#### 10.3a Folded into the deterministic core (T3/T7)

| Source domain(s) | Mechanism | Our feature | Ticket | Preconditions hold? |
|---|---|---|---|---|
| OAuth (RAR RFC 9396, incremental auth); agency law (limited POA, actual authority); military (positive control, ROE); medication (BCMA scan vs order); trading (15c3-5 pre-set limits) | Authority is pre-declared by the principal on a trusted channel. Content can request more but never grant it | **User-turn mandate:** a signed per-session grant `{tool, destination, max_amount, expires}` derived **only** from principal (user/system) turns. Calls outside it → deny (enforce) or hold. Content never widens it, and grants can only narrow (RFC 8693 `act` chain). Merged with destination provenance and per-tool policy into **one** `policy.json` evaluation (BACKLOG T3) | T3 | **Yes** for tool/destination/amount fields, which are structured. **Partial** for deriving the grant from free-text user turns, so it falls back to an operator template per task and ambiguity resolves to *narrower*. Per-session key, never a default secret (2013 EAS lesson). |
| Agency law (actual vs apparent authority); trading (fat-finger check); voice (speaker ID → provenance ID); military (tool output is intelligence, not orders) | A sensitive argument that traces only to untrusted content is "apparent-only" | Already T3 **destination provenance** and **source→sink**. Round 2 widens the extracted fields from destinations to **amounts and file paths** | T3 | **Yes**, same as §6a. |
| Medication (CPOE hard/soft stops; override rates 49–96%) | Hard-block a narrow tier, keep warnings rare, and track overrides per rule | **Per-rule override-rate tracking:** every hold/warn the human approves or denies is logged per rule. Rules overridden >90% are flagged to retire or tighten. Only a human can override, never the agent (an LLM's "reason" can be written by the injection) | T7 | **Yes.** Deterministic logging. Real override data needs S5's approval channel, and until then the benign corpus (T7 FP itemization) stands in for it. |
| Trading (order-rate throttles, Knight kill switch) | Velocity limits plus a halt | Already T3 **cumulative caps**. The kill switch = S6 breaker OPEN with a human reset | T3 / S6 | **Yes.** |
| Medication (tall-man lettering); supply chain (typosquatting) | Lookalike detection | Homoglyph / confusable + Levenshtein ≤2 check on destination hosts and tool names, as a T3 egress heuristic | T3 (heuristic) | **Partial.** A tripwire, not a boundary. |

#### 10.3b Stretch

| Source domain(s) | Mechanism | Our feature | Ticket | Preconditions hold? |
|---|---|---|---|---|
| Supply chain (lockfile/hash pinning, Socket capability diff, dependency confusion, xz tarball-vs-git gap) | Pin what you install, and diff capabilities rather than code | **Tool-manifest lockfile + capability diff:** `sentinel.lock.json` holds a sha256 per canonical `{name, description, inputSchema}`. A mismatch on `tools/list` → block or re-approve (rug pull). Capability tags (network, fs-write, shell, secrets, "instructs the model" phrases), with alerts only on *new* capabilities. Name-shadowing registry (same or near name from a second server, descriptions that mention another server's tools). Strip invisible Unicode/HTML comments | S10 (extends S9) | **Yes** for pinning and diffing. **Partial** for capability tags, which come from pattern-matching NL descriptions and can't be proven. Provenance proves the publisher, not runtime output. |
| Newsroom (CIA ACH: disconfirm, don't confirm); MELON (Zhu et al., ICML 2025) | Counterfactual test of whether untrusted content steered the call | **Counterfactual re-plan / masked re-execution as a *blocked-call explainer*:** for high-risk tools only, re-plan with untrusted chunks masked. If the call disappears, it was steered, and the case card says so. MELON is the published version, with masking in the **opposite** direction: it masks the *user prompt* and flags when the tool call survives, i.e. the call doesn't depend on the user | S11 | **Partial.** It needs the agent's planner to be replayable (DVAA canned responses may make this trivial or useless), costs an extra LLM call, and is an explainer and secondary signal only, never the gate (§10.1). |
| Voice assistants (cloud simultaneity detection, ≥3 households) | The same content triggering many principals at once is a broadcast/campaign | **Cross-session campaign correlation:** hash normalized imperative spans from tool outputs into a bounded counter. ≥K distinct sessions within T minutes → quarantine the span + alert | S12 | **Partial.** Needs fleet fan-out (fits Falcon's telemetry story). A one-off targeted injection never correlates. The counter is bounded and fails loud. |
| Newsroom (Admiralty grading; two independent sources / circular reporting) | Grade source reliability separately from claim credibility; corroborate from independent origins | Folded into S8/S11 as a risk input: a high-impact argument whose only origins are E/F-grade chunks escalates | (S8 input) | **Partial.** Web chunks have no reputation history, and grading must gate imperatives, not facts. |
| Military (challenge-reply nonce); medication (read-back); voice (approval card that echoes the intent) | The out-of-band confirmation restates the action and its source | Adds to **S5**: the approval card renders a canonical sentence ("send $400 to X, introduced by email from Y"). An optional one-time code is shown only in the operator terminal | S5 | **Yes.** Never in-band: an injected "user confirmed" spoofs a chat yes/no. |
| Military (two-person concept); medication (ISMP independent double-check) | A second, independent key for irreversible actions | Already S5 + S8's context-stripped judge. Round 2 adds that the second key should be a **human or a deterministic rule**, because two LLMs share failure modes | S5 / S8 | **Partial**, same as §6b. |

#### 10.3c Excluded or narrative only

| Source domain(s) | Mechanism | Why |
|---|---|---|
| Voice (static ad fingerprints) | Broadcast-fingerprint suppression: drop text matching known injection corpora | **Burger King re-dubbed within hours.** Text paraphrase costs less than re-dubbing audio. At most a telemetry signal (adds to the §6d SimHash exclusion) |
| Trading (LULD price bands) | Deviation band from a reference price | Agents have no reference price. The "baseline from the stated task" form is the S8 / mandate idea, not a learned band (the §6d exclusion still stands) |
| Agency law (liability allocation) | Who pays | Narrative and business framing only (§10.4). The law acts months later, and the proxy has milliseconds |
| Supply chain (reproducible builds, SBOM) | Rebuild-and-compare; inventories | LLM output is non-deterministic. An SBOM doesn't stop injection (audit only) |

### 10.4 New pitch lines

- **Trading:** "Wall Street learned in 2010 that every order passes a broker's risk gate before it reaches the
  market. SentinelProxy is that gate for AI agents."
- **Voice:** "In 2017 a TV anchor said 'Alexa, order me a dollhouse' and the living rooms of San Diego went
  shopping. Today every web page your agent reads is that anchor. SentinelProxy is the purchase PIN."
- **Medication:** "Pharmacies stopped forged prescriptions by never trusting the paper, only the callback.
  Content can request an action; only the principal's own channel can authorize it."
- **Military:** "Militaries never let a radio message launch a missile. Orders come from the authenticated
  chain of command; everything else is intelligence."
- **Supply chain:** "npm has a lockfile. Your agent's tools don't."
- **OAuth:** "OAuth solved the confused deputy for apps by making authority explicit, scoped, audience-bound
  and consented on a trusted channel. SentinelProxy does the same for every tool call."
- **Agency law (business framing):** "Your AI agent holds your power of attorney. The law already says the
  principal pays (*Moffatt v. Air Canada*), so SentinelProxy limits what it can be talked into doing."
- **Newsroom:** "Sources inform, they never assign."
- **Empirical (for a judge who asks "why not a classifier?"):** "Spam filters lost to spammers because the
  attacker wrote the content being scored. DKIM won because the mail server enforced it. We enforce at the boundary."

### 10.5 What doesn't transfer (round 2)

- **Numeric risk.** Trading limits sum notional value. Agent harm is semantic, so limits need **typed per-tool
  schemas**, and free-text args only get provenance checks (trading).
- **Coarse, session-level grants.** An OAuth scope, once granted, can be used by any instruction. The mandate must be checked **per call** and
  argument-level (OAuth).
- **Self-reported provenance.** An LLM can't reliably say which span caused an action, so provenance is
  computed by the proxy, never asked of the model (OAuth `sourceArn`, newsroom).
- **Biometrics and physical labels.** Agents have no voice to enroll and no barcode, so provenance is tracked, not
  sensed (voice, medication).
- **In-band confirmation.** A spoken yes/no or a "user confirmed" in the chat is spoofable (voice, military).
- **Trained, accountable humans.** Licensure, liability and discipline deter human deputies. An LLM has none of them, so
  enforcement lives in the proxy (medication, military, agency law, newsroom).
- **Two-LLM two-key.** The two models share failure modes, so the second key should be a human or a deterministic rule (military, medication).
- **Fixed order vocabulary.** Military read-back works on a small lexicon. Agent tasks are open-ended, so fuzzy
  matching produces false positives (military).
- **Simultaneity against targeted attacks.** A single poisoned email never correlates across sessions (voice).
- **Human timescales.** Newsroom verification, legal remedy and registry quarantine take hours to months (newsroom, agency law,
  supply chain).
- **Warn-everything designs.** 49–96% of CPOE alerts are overridden, so warnings alone protect almost nothing (medication).

### 10.6 Mapping back to BACKLOG

- T3: the **user-turn mandate** is merged with destination provenance and per-tool policy into one config.
- T7: **per-rule override-rate tracking**.
- S10 tool-manifest lockfile + capability diff, S11 counterfactual re-plan explainer, S12 cross-session
  campaign correlation. S5 gets the read-back card. S8's deterministic map is subsumed by the mandate's `tool` field.

### 10.7 Citations (round 2)

**⚠ = the source report flagged this as unverified, written from memory, or seen only in a search snippet. Check it before it goes on a slide.**

**Empirical transfer cases** (4 web searches; the rest from memory)
- Haynes 2009 (NEJM), surgical checklist: https://news.harvard.edu/gazette/story/2009/01/surgical-safety-checklist-drops-deaths-and-complications-by-more-than-one-third/
- Urbach 2014, Ontario: https://psnet.ahrq.gov/issue/introduction-surgical-safety-checklists-ontario-canada
- Kim et al. 2007, AIS for IDS: https://arxiv.org/pdf/0804.1266
- Staniford, Paxson, Weaver 2002 (related Code Red paper): https://www.cs.ucf.edu/~czou/research/codered.pdf (⚠ original USENIX URL unverified)
- Lowd & Meek 2005 (secondary source): https://en.wikipedia.org/wiki/Bayesian_poisoning
- Whitten & Tygar 1999: https://www.usenix.org/conference/8th-usenix-security-symposium/why-johnny-cant-encrypt-usability-evaluation-pgp-50
- DMARC after the 2024 bulk-sender rules: https://betanews.com/2025/02/05/rate-of-dmarc-adoption-doubles-thanks-to-bulk-sender-requirements/
- ⚠ Graham, "A Plan for Spam": http://www.paulgraham.com/spam.html
- ⚠ Freeman et al., NDSS 2016, "Who Are You?"
- ⚠ DORA / Accelerate: https://dora.dev
- ⚠ HACCP history: https://www.fda.gov/food/hazard-analysis-critical-control-point-haccp

**Algorithmic trading** (3 searches)
- AP hack, 23 Apr 2013 (verified via search): https://www.csmonitor.com/layout/set/amphtml/USA/2013/0423/Hackers-compromise-Associated-Press-Twitter-account-tweet-false-report-of-White-House-attack
- Knight Capital 15c3-5 settlement, $12M (verified via search): https://www.wilmerhale.com/insights/client-alerts/knight-capital-settles-rule-15c3-5-violations-with-sec-agrees-to-pay-12-million
- FINRA, Market Access Rule (verified via search): https://www.finra.org/rules-guidance/guidance/reports/2022-finras-examination-and-risk-monitoring-program/market-access-rule
- ⚠ SEC Release 34-70694: https://www.sec.gov/litigation/admin/2013/34-70694.pdf
- ⚠ LULD plan: https://www.luldplan.com

**Voice assistants**
- The Register, dollhouse: https://www.theregister.co.uk/2017/01/07/tv_anchor_says_alexa_buy_me_a_dollhouse_and_she_does/ (reports describe *attempted* orders; no confirmed completed-order count)
- Snopes, dollhouse: https://www.snopes.com/alexa-orders-dollhouse-and-cookies/
- Burger King re-dubs: https://adland.tv/burger-king-redubs-connected-whopper-ad-triggers-google-devices-again
- DolphinAttack (CCS 2017): https://arxiv.org/abs/1708.09537
- ⚠ Amazon Science, two-tier fingerprinting / 3-household rule (search summary only, page not opened; the "80–90%" figure is from it): https://amazon.science/blog/why-alexa-wont-wake-up-when-she-hears-her-name-in-amazons-super-bowl-ad
- ⚠ Amazon help, voice code (odd survey subdomain): https://digprjsurvey.amazon.com/csad/help/node/GAA2RYUEDNT5ZSNK

**Medication safety** (no searches run; **all ⚠**, including the override-rate figures)
- ⚠ van der Sijs et al., JAMIA 2006 (49–96% overrides): https://pubmed.ncbi.nlm.nih.gov/16357358/
- ⚠ Isaac et al., Arch Intern Med 2009 (~90% high-severity overridden): https://pubmed.ncbi.nlm.nih.gov/19204211/
- ⚠ Nanji et al., JAMIA 2018 (~73% overridden): https://academic.oup.com/jamia/article/25/5/476/4705617
- ⚠ Koppel et al., JAMIA 2008 (BCMA workarounds): https://pubmed.ncbi.nlm.nih.gov/18436903/
- ⚠ ISMP high-alert medications: https://www.ismp.org/recommendations/high-alert-medications-acute-list
- ⚠ CDC on PDMPs: https://www.cdc.gov/overdose-prevention/hcp/clinical-guidance/prescription-drug-monitoring-programs.html

**Military / emergency order authentication** (3 searches; all ⚠ *seen in search results, not opened*; the authenticator-table and read-back descriptions are general knowledge without a citation)
- ⚠ FCC Hawaii false-alert report (via NPSTC): https://blog.npstc.org/?p=6859
- ⚠ NPR, "don't say 'this is not a drill'": https://www.npr.org/sections/thetwo-way/2018/04/11/601394064/federal-communications-commission-dont-say-this-is-not-a-drill-during-drills
- ⚠ CSM, EAS zombie hack: https://www.csmonitor.com/USA/2013/0214/Why-zombie-cyberattack-is-a-real-concern-for-Emergency-Alert-System
- ⚠ The Register, EAS vulnerabilities: https://www.theregister.com/2013/02/18/eas_vulns/
- ⚠ AFGSC, positive control: https://www.afgsc.af.mil/News/Features/Display/Article/629957/the-myth-of-the-big-red-button-how-the-icbm-force-maintains-positive-control-nu
- ⚠ DOE, Two-Person Concept: https://www.directives.doe.gov/terms_definitions/two-person-concept-tpc

**Software supply chain** (no fetches; **all ⚠**)
- ⚠ CISA AA20-352A (SolarWinds): https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
- ⚠ CrowdStrike SUNSPOT analysis (exact path unverified): https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/
- ⚠ Freund's xz disclosure: https://www.openwall.com/lists/oss-security/2024/03/29/4
- ⚠ Birsan, Dependency Confusion: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- ⚠ SLSA v1.0 levels: https://slsa.dev/spec/v1.0/levels
- ⚠ npm provenance: https://docs.npmjs.com/generating-provenance-statements; Socket: https://socket.dev (feature details unverified)

**OAuth / delegated authorization**
- MCP Authorization spec 2025-06-18 (verified): https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- AWS IAM confused deputy, ExternalId/SourceArn (verified): https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- ⚠ IETF draft, agent on-behalf-of (verified via search; the "expired Feb 2026" and "OAuth WG rechartered Jun 2026" claims were not opened): https://datatracker.ietf.org/doc/html/draft-oauth-ai-agents-on-behalf-of-user-02
- ⚠ RFC 9396 (RAR), not fetched: https://www.rfc-editor.org/rfc/rfc9396
- ⚠ RFC 8693 (Token Exchange), not fetched: https://www.rfc-editor.org/rfc/rfc8693
- ⚠ Microsoft, illicit consent grants: https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants

**Agency law** (Restatement §§2.01–2.03, 4.01, 8.01 cited from memory ⚠)
- ⚠ *Moffatt v. Air Canada*, 2024 BCCRT 149 (search result, not opened): https://www.dww.com/articles/bc-tribunal-finds-air-canada-liable-for-inaccurate-advice-given-by-website-chatbot
- ⚠ UCC §3-404 (search result, not opened): https://www.law.cornell.edu/ucc/3/3-404
- ⚠ EU Directive 2024/2853 (the 9 Dec 2026 date comes from secondary summaries): https://eur-lex.europa.eu/EN/legal-content/summary/defective-products-liability.html
- ⚠ Venable, "Rogue AI Agents Won't Be Testifying — You Will" (Apr 2026, snippet only): https://www.venable.com/insights/publications/2026/04/rogue-ai-agents-wont-be-testifying-you-will
- ⚠ Restatement §2.03 applied to AI agents (blog, not primary): https://blog.promise.legal/ai-agent-legal-liability-contracting-authority/
- ⚠ Baker McKenzie, US accountability for AI agents (Jun 2026): URL malformed, unverified

**Newsroom source verification** (no searches; **all ⚠**)
- ⚠ Heuer, *Psychology of Intelligence Analysis* (1999): https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/
- ⚠ Thornburgh–Boccardi report (CBS, 2005): https://www.cbsnews.com/htdocs/pdf/complete_report/CBS_Report.pdf
- ⚠ Admiralty code: https://en.wikipedia.org/wiki/Admiralty_code
- ⚠ Syrian Electronic Army / AP hack: https://en.wikipedia.org/wiki/Syrian_Electronic_Army (the "$136B" figure is unverified)
- ⚠ *Verification Handbook*: https://datajournalism.com/read/handbook/verification-3
- ⚠ Curveball / circular reporting: https://en.wikipedia.org/wiki/Curveball_(informant)

**Added by T0c (verified 2026-10-12 via web search)**
- Zhu, Yang, Wang, Guo, Wang, "MELON: Provable Defense Against Indirect Prompt Injection Attacks in AI Agents",
  ICML 2025 (PMLR 267). https://arxiv.org/abs/2502.05174, https://proceedings.mlr.press/v267/zhu25z.html.
  It masks the user prompt, re-executes, and flags an attack when the masked and original runs produce similar tool calls. Evaluated on AgentDojo.
