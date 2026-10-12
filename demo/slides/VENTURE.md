# Venture slide: SentinelProxy as a product (Ciocca Venture Award)

One slide for @c-awad's 18:00 deck, plus about 30 seconds of speaker notes. Mo on #131: "Ciocca is a go".
Every number on this slide comes from `sentinel/scoring/results.json`. There are no invented market figures or customers.

Ciocca criteria (issue #128, verbatim): "the clarity of the problem they're solving, who would use and pay for their
solution, how it stands apart from existing tools, and a credible path from prototype to launch, alongside a working demo."

---

## Slide content

**Title:** SentinelProxy: a drop-in egress guard for tool-using agents

**Problem.** Agents with tools read untrusted text (tickets, docs, web pages). An indirect prompt injection hidden in
that text makes the agent send private data out with the user's authority. This is the "lethal trifecta": private
data, untrusted content, external communication.

**Who uses it and who pays.**
- **User:** the platform or AppSec engineer who ships an internal or customer-facing agent on an OpenAI-compatible API.
- **Buyer:** the head of engineering or security at a mid-size software company that is shipping agents and has no
  enterprise AI detection-and-response (AIDR) budget yet. Their problem is "we can't ship this agent until security signs off on what it can send out".

**How it stands apart** (we are *not* a better classifier):

| | What it is | Where SentinelProxy fits |
|---|---|---|
| Falcon AIDR | CrowdStrike's enterprise AI detection and response platform | We complement it at the tool boundary. We have not integrated with it. Our alerts use an AIDR-shaped schema |
| NeMo Guardrails | NVIDIA's open-source toolkit of programmable rails inside the app | We need no app code changes: a sidecar in front of the chat endpoint plus an egress proxy |
| Lakera Guard, Prompt Guard | Classifiers that score text for injection or jailbreak | We decide on **where data goes**, not on how the text reads. Pair us with one of them |

Our edge, in four parts: **drop-in sidecar** · **default-deny egress at the tool boundary** · **deterministic rules**
(same input, same verdict) · **low false-positive posture**.

**Path to launch.**
1. **Open-source sidecar** (today): reverse proxy plus egress guard, run in observe mode first, then block.
2. **Managed policy and alert routing**: hosted allowlists and honeytoken registry, with alerts routed to the tools a team already uses.
3. **SOC integration**: alerts go into analyst triage. This already works offline as a prototype with our Track 1 SOC Brief (`scripts/soc-handoff.sh`).

**Evidence (from `results.json`).** Where data actually leaves, we prevent **57 of 71** exfil attempts with **0 of 164**
legitimate requests blocked. DVAA's own scanner prevents 64 of 71 but blocks 21 of 164.

---

## Speaker notes (about 30 seconds, about 80 words)

"Agents read untrusted text and act with your authority, so one hidden instruction can send customer data out.
Who pays: a mid-size software team shipping agents on OpenAI-compatible APIs, without an enterprise AIDR budget.
We're not a better classifier. We're a drop-in sidecar that default-denies where data can go. Where data actually
leaves, we prevent 57 of 71 attempts with zero of 164 legitimate requests blocked. The baseline stops 64 but blocks 21.
Path: open-source sidecar, then managed policy, then SOC integration."

## Do not say
- Any market size, price point, customer name, or "customers are asking". We have none of these.
- "Better than Lakera / Prompt Guard / AIDR at detection." We didn't benchmark them.
- "57 of 71" on its own: always say the baseline's 64 of 71 at 21 of 164 blocked in the same breath.
- "Integrated with Falcon." It's an AIDR-*shaped* schema only.
