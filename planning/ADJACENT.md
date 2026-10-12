# ADJACENT — what other fields already know about our problem

> Operator prompt: *"explore the adjacent knowledge angle… consider what makes knowledge adjacent, is it
> transferable based on the actor"*.
>
> Sources: eight parallel research reports (T0b), covering analogical-transfer theory plus seven domains:
> software injection, BEC / social engineering, counterintelligence, fraud / AML, safety engineering /
> aviation, HACCP / food safety, and immunology. This file follows the theory report's framing. The
> mechanism catalog (§6) feeds the T3/T4/T5/T7 acceptance criteria and the stretch tickets in BACKLOG.md.

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

**Is knowledge transferable based on the actor?** Partly. No single dimension decides it:
- **Actor triad + shared channel** decide whether a field is *relevant*, i.e. whether its threat model applies.
- **Adversary adaptivity** decides whether the field's defenses *survive* contact with a prompt injector
  who reads our detector.
- **Choke point + ground-truth feedback** decide whether a defense is *buildable* in our setting.

So the actor structure is the entry ticket. Whether a given defense transfers is a separate question,
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
AML's triad is weaker. **Treat totals as a guide, not as the rank.**

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
