# Q&A prep: the hardest judge questions

For the presenter. Each answer is 2–4 sentences you can say out loud, followed by a **Proof** line you can point to.
Numbers come from **the current `sentinel/scoring/RESULTS.md`**. A final rescore lands around 15:00, so re-read the
headline line before 18:00 and say the figure that is there. Citation wording comes only from `planning/CITATIONS.md`.

---

## The critic's top 5 (issue #112): answer these first, short and honest

**C1. "Your defense prevents less than the vulnerable target's own scanner (41.8% vs 63.0%). Why deploy it?"**
"On the blended corpus, it does, and we lead with that. Most of the gap is injection-only text that steals nothing:
there we prevent 18.6% against its 46.6%. Where data actually leaves, we prevent 80.3% (57 of 71) against its 90.1%,
and its scanner also flags 21 of 164 benign cases, 12.8%. Our point is that regex at the front door isn't enough; the
control that actually blocks is default-deny egress at the tool boundary."
**Proof:** `sentinel/scoring/RESULTS.md` headline table and "Recall by positive kind (prevention)".

**C2. "Held-out prevention is 0 of 600, and detection drops from 67.7% to 28.5%. That's overfitting."**
"Partly, yes. We ran that held-out set on ourselves and published it. None of those 600 public jailbreak rows has a
destination to send data to, so our exfil rule has nothing to block; DVAA prevents 60.7% of them because it is a
jailbreak scanner. We're an exfil guard, not a jailbreak classifier: pair us with one, such as Prompt Guard. The
detection drop is real, and recall on novel phrasings is limited."
**Proof:** `captures/holdout-hf/RESULTS.md` (T3 0.285 detection, 0.000 prevention, 0/400 benign blocked).

**C3. "DVAA is offline with canned responses. You've never faced a real LLM, and you don't prevent DVAA's own captures."**
"Correct, and we say "deterministic sandbox, no LLM" in the first 20 seconds. A real model that paraphrases, splits or
encodes its exfil is untested. In the scoring corpus, all 5 recorded DVAA exploit captures are detected but none is
counted as prevented request-side, because the tool ran in-process; for those, the egress guard is the prevention
story, and in its recorded run the attacker server received nothing."
**Proof:** `results.json` `detectors.t3.perCase` (`attack/*`: `detectedAny: true`, `preventedEnforce: false`);
`demo/captures/egress-demo-block.txt` (`RESULT block: PREVENTED`, no canary hits).

**C4. "Zero false positives on 164 benign cases you tuned against isn't evidence. And one regex does all the prevention."**
"Both fair. 0 of 164 is a small sample on a set the rules were tuned on, so we don't claim a zero-FP rate. And yes:
all 79 scored preventions fire one pre-forward rule, `inbound.exfil_instruction`. Honeytokens, provenance and taint
are tripwires and alerts, not the engine."
**Proof:** RESULTS.md (TN 164, FP 0); `results.json` perCase (every prevented positive lists `inbound.exfil_instruction`).

**C5. "This is a regex plus a host allowlist. Calling it a slice of Falcon AIDR is overreach, and spacing out an IBAN bypasses it."**
"Agreed on the name: we dropped it. It's an exfil-focused guardrail for tool-using agents that complements AIDR at the
tool boundary; we haven't integrated with Falcon. The spaced-IBAN bypass is real, our own critic found it, and
destination canonicalization would close it, but it isn't merged. The blocking verbs are also English only."
**Proof:** issue #112, section 4 (mutation table).

---

## The rest

**1. "DVAA's own scanner prevents more attacks than yours. Why would anyone deploy yours?"**
"On prevention, yes: DVAA's scanner stops more, 63.0% against our 41.8%, but it does it with a 12.8% benign
false-positive rate, flagging 21 of the 164 benign cases in our corpus. On detection we're now slightly ahead,
67.7% against 65.6%, with 0 of the 164 benign cases blocked (a set we also tuned on, so not a zero-FP guarantee). We also catch both cases
where the injection hides between DVAA's head and tail 8KB windows (2 of 2), which their scanner can't see. Every
miss is listed openly in RESULTS.md."
*FP caveat, say it if asked:* "Held-out benign: 1/32 blocked (a security-awareness memo quoting an injection phrase; same as before #46), and 4/32 raise an alert without a block. Held-out attacks: 14 of 16 hand-written paraphrases detected, but on an independent reviewer's 6 further paraphrases, 1 detected, so recall on novel phrasings is limited — see PR #46."
*After the 15:00 rescore:* re-read the RESULTS.md headline and use the figures that are there.
**Proof:** RESULTS.md headline table (t3 against dvaa-baseline, both lenses), the 8KB-evasion (`evadesBaseline`) block, and
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
alert. The recorded contrast block came from the shipped T3 detector, not a simplified inspector
(`captures/contrast/runs/run-meta.json`: `inspector: detector:sentinel-t3`, `inspector_config_is_standin: false`).

**3. "The dashboard says Blocked, but the canary got the data?"**
"Those are two different runs. In the unprotected run SentinelProxy only observes. DVAA runs tools inside its own
process, so anything we see after execution is detection only, with an alert and evidence. In the protected runs we
prevent: a 403 before the request is forwarded, so the agent never runs, and an egress deny at the tool boundary.
The attacker server receives nothing. Response-side findings stay alert-only for prevention; in block mode they
withhold the reply, but the tool has already run."
**Proof:** `contrast.json`: in observe mode, `exfilExecuted: true` and `canaryHits: 1` ("DETECTED, NOT PREVENTED").
In block mode, `proxyStatus: 403`, `agentInvoked: false` and `canaryHits: 0`. `scripts/egress-demo.sh both` uses the
attacker server's receipt as ground truth, never DVAA's own flag.

**4. "Why not an LLM classifier?"**
"Three reasons: latency, determinism, and adaptive attackers. Our median detector time is under a tenth of a millisecond per case (RESULTS.md headline) with no model call, so the same
input always gets the same verdict, and a classifier can't be prompt-injected through the content it scores. Spam
filters lost because the attacker wrote the content being scored. DKIM won because the mail server enforced it.
We enforce at the boundary, and classifiers stay a secondary signal."
**Proof:** RESULTS.md median latency. `planning/ADJACENT.md` §10.1 and §10.4 (the spam-filter lesson).

**5. "How does this map to Falcon AIDR and AgentWorks?"**
"It's an exfil-focused guardrail at the tool boundary, not a slice of AIDR. Our alerts use an AIDR-shaped
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
Run it in observe mode first to measure false positives on your own traffic, then switch to block."
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
"No machine-learning classifier and no TLS interception. Egress events are tied to chat turns only by best-effort time-window
attribution, and stand alone when that is ambiguous. Response-side checks are alert-only for prevention, because DVAA runs its tools inside its own process (block mode still withholds the reply). Alert redaction has
known gaps, such as double-percent-encoded and `\u`-escaped canaries, even though egress decodes them for blocking.
Finally, there's no live LLM in the demo, and no Falcon API integration."
**Proof:** the "Honest limitations" section of the README (PR #47) and "Known limitations" in PR #45 (T12).

**11. "Your prevention recall is 41.8% and DVAA's is 63.0%. Isn't theirs just better at stopping attacks?"**
"On that number, yes, theirs is higher, and we say so. (On detection we're now slightly ahead.) But the two figures count different things. DVAA's
'prevention' is a scanner hit on the request, and it comes with a 12.8% benign false-positive rate. Ours counts only
what is actually stopped before the agent acts: a pre-forward block or an egress deny, plus a withheld reply in block
mode. Alert-only findings count as detection, never as prevention. On the 164-case benign corpus that number carries
0 false positives."
**Proof:** RESULTS.md headline table (both lenses, both detectors) and the "Honest lenses" paragraph. Re-read the
figures after the 15:00 rescore.

**12. "What does the proxy add end to end?"**
"The detector itself runs at a median under a tenth of a millisecond, p95 around half a millisecond per case. The whole proxy hop, measured on loopback, added a
median of 1.28 ms for a small request and 5.86 ms for a 79 KB one. On our own OpsBot (Path A), the median turn goes
from 2.5 ms undefended to 8.7 ms behind both the chat proxy and the egress guard. These are loopback numbers with no
LLM in the loop, so a real model call dwarfs them."
**Proof:** PR #67 (proxy bench). `track3a/RESULTS.md` latency column.

**13. "Isn't this overfit to your own corpus? How does it generalize?"**
"Partly a fair worry, and we measured it. On 32 hand-written held-out benign docs, 1 was blocked: a security-awareness
memo quoting an injection phrase, the same as before #46.
4 of the 32 raise an alert, not a block. On 16 paraphrased held-out attacks, we detect 14 and block 1. PR #46 raised detection from 2 to 14 with alert-only structural signals; it
did not add blocks. That 14 of 16 is optimistic: on an independent reviewer's 6 further paraphrases, 1 was detected,
so recall on novel phrasings is limited. A larger held-out set from public data is still pending, so we don't quote it."
**Proof:** PR #46, "Held-out (hand-written, not corpus)" table, with no post-hoc tuning.

**14. "What about streaming responses and multi-turn conversations?"**
"Multi-turn is handled: clients resend the history, and the detector keys a session on the `x-sentinel-session`
header or a hash of the opening turns, so provenance and the user's mandate are judged over the whole conversation.
Streaming is a limitation. The proxy buffers the full upstream response, up to a hard cap, before it inspects and
replies, so a streamed reply loses incremental delivery, and an oversize one is refused with a 502 and an alert, never
passed through unscanned. Our response-side parsing targets JSON completions; we haven't tested server-sent events
against it. DVAA doesn't stream."
**Proof:** `sentinel/proxy/server.mjs` (`forward()` buffers with a hard cap; over cap → 502 + ALERT).
`sentinel/detectors/src/inspector.js` (session key) and `sentinel/detectors/src/bounds.js` (history bounds).

**15. "How much of the demo is live?"**
"Only Beat 4's 200 and 403 are live: a real request through the shipped proxy to running DVAA. Beats 3, 3b, 4b and
5a, and the alert half of Beat 4, replay real recordings of runs against live DVAA, and we say "recorded" on each.
The headline numbers are read from the committed scoring output, which anyone can regenerate with
`scripts/eval.sh score`."
**Proof:** `demo/run-demo.sh` (live Beat 4, with a WARN and fallback to the recording if the live proxy is down),
`captures/` and `demo/captures/egress-demo-block.txt`.

**16. "How does it do on generic jailbreaks?"**
"Not well at blocking, by design. On a held-out set of 600 attacks and 400 benign cases from three public Hugging Face
jailbreak and injection sets, none of which point data anywhere, we detected 28.5%, prevented 0%, and had 0 of 400
false positives. By set, we detected 58% of Gandalf, 19% of SPML and about 8% of jailbreak-classification. DVAA's
scanner detected and prevented 60.7%, with 22 of 400 false positives (5.5%). SentinelProxy blocks only when an
injection tries to move data to a destination or misuse a tool, so it's an exfiltration and tool-misuse guardrail,
not a general jailbreak classifier. Generic jailbreak text with no action is alerted at most. Pair it with a jailbreak
classifier such as Prompt Guard."
**Proof:** held-out; see #84 and `captures/holdout-hf/RESULTS.md`.

---

### If you blank
1. **Provenance, not keywords:** content can ask for something. Only the user's own turn can authorize it.
2. **Where data actually leaves, we prevent 80.3% (57 of 71).** DVAA prevents more overall (63.0% vs 41.8%), mostly on
   injection-only text that steals nothing, and flags 12.8% of benign traffic; we blocked 0 of 164 benign (a tuned set). Held-out caveat: Held-out benign: 1/32 blocked (a security-awareness memo quoting an injection phrase; same as before #46), and 4/32 raise an alert without a block. Held-out attacks: 14 of 16 hand-written paraphrases detected, but on an independent reviewer's 6 further paraphrases, 1 detected, so recall on novel phrasings is limited — see PR #46.
3. **Detection and prevention are reported separately.** Alerts after execution only detect. A 403 or egress deny prevents.
4. **Everything fails closed, nothing is silently truncated.** Too big, too slow, or an error: deny and alert.
5. **Every miss is listed in RESULTS.md, and we attacked ourselves:** 0% held-out prevention, spaced-IBAN bypass. Default-deny egress is the control that blocks.
6. **Scope:** we stop injection-driven exfiltration and tool misuse; generic jailbreaks are for a classifier such as Prompt Guard.
