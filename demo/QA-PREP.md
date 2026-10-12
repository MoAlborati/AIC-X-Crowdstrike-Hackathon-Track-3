# Q&A prep: the 10 hardest judge questions

For the presenter. Each answer is 2–4 sentences you can say out loud, followed by a **Proof** line you can point to.
Numbers come from **the current `sentinel/scoring/RESULTS.md`**. A final rescore lands around 15:00, so re-read the
headline line before 18:00 and say the figure that is there. Citation wording comes only from `planning/CITATIONS.md`.

---

**1. "DVAA's own scanner has higher recall. Why would anyone deploy yours?"**
"Because theirs blocks your users. In our corpus it flags 21 of 164 benign requests, a 12.8% false-positive rate.
We flag 0 of 164, at 100% precision. We also catch both cases where the injection hides between DVAA's head and
tail 8KB windows (2 of 2), which their scanner can't see. Every miss is listed openly in RESULTS.md."
*If PR #46 has merged by then, add:* "With the structural signals, our detection is 83.1% against their 65.6%,
still with zero benign false positives."
**Proof:** RESULTS.md headline table (t3 against dvaa-baseline, both lenses), the "Beats DVAA baseline" block, and
the "False negatives" list. PR #46 has the before/after rescore table.

**2. "The document arrived in the user turn. Isn't this just an input filter?"**
"No. We decide on provenance, not keywords. The mandate is derived only from the principal's own words, and any
document pasted inside that turn is treated as untrusted content. If that content asks to send data to a
destination the user never named, it's `payee_not_confirmed`: Confirmation of Payee for agents. Replace the canary URL
with any other host and the request is still blocked before it's forwarded. When the agent reads the document
inside its own process, the block happens at the egress guard on the tool boundary, which never sees the prompt."
**Proof:** `sentinel/detectors/src/mandate.js` (header: "principal turns, excluding untrusted segments embedded in
them"). `test/taint.test.js` RAGBot test (reason codes `injection_markers` and `payee_not_confirmed`, with no
honeytoken needed). `test/mandate.test.js` ("content can never widen the grant").
*Honest edge case:* if every destination is removed, there's nowhere to exfiltrate to, so the request only raises an
alert. The recorded contrast block used a stand-in substring inspector. It proves the block path, not detection
quality (`captures/contrast/runs/contrast.json`).

**3. "The dashboard says Blocked, but the canary got the data?"**
"Those are two different runs. In the unprotected run SentinelProxy only observes. DVAA runs tools inside its own
process, so anything we see after execution is detection only, with an alert and evidence. In the protected runs we
prevent: a 403 before the request is forwarded, so the agent never runs, and an egress deny at the tool boundary.
The attacker server receives nothing."
**Proof:** `contrast.json`: in observe mode, `exfilExecuted: true` and `canaryHits: 1` ("DETECTED, NOT PREVENTED").
In block mode, `proxyStatus: 403`, `agentInvoked: false` and `canaryHits: 0`. `scripts/egress-demo.sh both` uses the
attacker server's receipt as ground truth, never DVAA's own flag.

**4. "Why not an LLM classifier?"**
"Three reasons: latency, determinism, and adaptive attackers. Our median is 0.067 ms with no model call, so the same
input always gets the same verdict, and a classifier can't be prompt-injected through the content it scores. Spam
filters lost because the attacker wrote the content being scored. DKIM won because the mail server enforced it.
We enforce at the boundary, and classifiers stay a secondary signal."
**Proof:** RESULTS.md median latency. `planning/ADJACENT.md` §10.1 and §10.4 (the spam-filter lesson).

**5. "How does this map to Falcon AIDR and AgentWorks?"**
"It's a working slice of Falcon AI Detection and Response at the tool boundary. Our alerts use a Falcon/AIDR-shaped
schema, mapped to MITRE ATLAS, ATT&CK T1567/T1041, and OWASP LLM and Agentic. AgentWorks makes every security team an
AI builder, and those are exactly the tool-using agents this guards. We complement AIDR's content detection with
provenance and egress controls. We don't replace it, and we haven't integrated with Falcon's APIs."
**Proof:** `sentinel/alerts` (T4 schema), the alert JSON in `sentinel/egress/evidence-block.jsonl`, and the
CITATIONS.md rows for AIDR and AgentWorks. Use "announced" for AgentWorks.

**6. "What about HTTPS egress?"**
"That's a known limitation. We don't intercept TLS. A CONNECT tunnel is decided on host alone, against an exact-host
allowlist, so an unknown host is still denied but we can't read its payload. DVAA's exfiltration sinks use plain HTTP,
so we see their full contents. In production you'd add TLS inspection at the egress proxy or rely on the
allowlist."
**Proof:** `sentinel/egress/inspector.mjs` header comment ("CONNECT … allow/deny by host allowlist only"). The first
line of `evidence-block.jsonl` is a CONNECT deny with `destination_not_allowlisted`.

**7. "What happens under load, or with an oversized payload?"**
"It fails closed, and every limit is bounded. An oversized request gets a 413 and an alert. If the inspector errors in
block mode, the request gets a 503 and an alert. If the detector throws or overruns its time budget, it blocks and
alerts. Nothing is ever forwarded unscanned. At
egress, an oversized payload, too many layers of encoding, or a scan timeout gets denied, even in observe mode. We
scan the full payload, so no limit ever leads to a decision made on partial data."
**Proof:** the proxy's `maxRequestBytes` of 1 MiB (`sentinel/proxy/README.md`). The egress limits `MAX_EGRESS_BYTES=65536`
and `SCAN_BUDGET_MS=250`. The 40 ms detector budget (PR #42). The "Bounds" section of `docs/ARCHITECTURE.md` (PR #47).

**8. "How would you deploy this for real?"**
"In two places. A sidecar reverse proxy goes in front of the agent's chat endpoint, and an egress forward proxy is
the agent's only route out. In our compose setup the agent sits on an internal network whose only exit is the guard.
Run it in observe mode first to measure false positives, then switch to block."
**Proof:** `sentinel/egress/compose.egress.yml`. `scripts/egress-demo.sh both` also checks that dialing out directly
around the guard fails.

**9. "What's your false-negative story?"**
"We publish it. RESULTS.md lists every attack we miss and every attack we detect but don't prevent. Most of the
misses are injection-only prompts with no exfiltration attempt, such as deepset role-play rows, where blocking would
also block legitimate users. Whether to alert or block is a policy choice. We block when untrusted content plus an
unconfirmed destination appears, and we only alert on injection markers alone."
**Proof:** RESULTS.md `## t3`: recall by positive kind (exfiltration against injection-only), "Detected but NOT
prevented", and "False negatives". PR #46 lists its remaining misses and explains why it didn't chase them.

**10. "What did you NOT build?"**
"No machine-learning classifier and no TLS interception. We don't correlate egress events with chat turns, and
response-side checks only raise alerts, because DVAA runs its tools inside its own process. Alert redaction has
known gaps, such as double-percent-encoded and `\u`-escaped canaries, even though egress decodes them for blocking.
Finally, there's no live LLM in the demo, and no Falcon API integration."
**Proof:** the "Honest limitations" section of the README (PR #47) and "Known limitations" in PR #45 (T12).

---

### If you blank
1. **Provenance, not keywords:** content can ask for something. Only the user's own turn can authorize it.
2. **0 of 164 benign false positives**, against DVAA's 12.8%, and we catch 2 of 2 attacks hidden past the 8KB window.
3. **Detection and prevention are reported separately.** Alerts after execution only detect. A 403 or egress deny prevents.
4. **Everything fails closed, nothing is silently truncated.** Too big, too slow, or an error: deny and alert.
5. **Every miss is listed in RESULTS.md.** We complement Falcon AIDR at the tool boundary.
