# Venture slide: Tourniquet as a product (Ciocca Venture Award)

*A tourniquet stops the bleed: Tourniquet stops data exfiltration (the "bleed") and other agent tool-misuse vulnerabilities at the egress boundary.*

One slide for @c-awad's 18:00 deck, plus about 30 seconds of speaker notes. Mo on #131: "Ciocca is a go".
Every number on this slide comes from `sentinel/scoring/results.json`. There are no invented market figures or customers.

Ciocca criteria (issue #128, verbatim): "the clarity of the problem they're solving, who would use and pay for their
solution, how it stands apart from existing tools, and a credible path from prototype to launch, alongside a working demo."

---

## Slide content

**Title:** Tourniquet: a drop-in egress guard for tool-using agents

**Problem.** Agents with tools read untrusted text (tickets, docs, web pages). An indirect prompt injection hidden in
that text makes the agent send private data out with the user's authority. This is the "lethal trifecta": private
data, untrusted content, external communication.

**Who uses it and who pays.**
- **Buyer in one line:** teams running agents they can't rebuild. That means a vendor agent, an open-source agent, or a legacy internal one, where you can't rewrite the prompts or the tool code but you can control its network.
- **User:** the platform or AppSec engineer who ships an internal or customer-facing agent on an OpenAI-compatible API.
- **Budget holder:** the head of engineering or security at a mid-size software company that is shipping agents and has no
  enterprise AI detection-and-response (AIDR) budget yet. Their problem is "we can't ship this agent until security signs off on what it can send out".

**Wedge:** an egress sidecar for agent tool calls. It is one container that becomes the agent's only route out. It needs no code changes and no model changes, and it runs in observe mode first.

**On-box / data-residency wedge.** Because it is a self-hosted sidecar with deterministic rules and no outbound model call, the decision never leaves the box. That fits on-premises, air-gapped and data-residency-constrained deployments, and regulated industries (finance, healthcare, government) where sending agent traffic to a third-party classifier cloud is a non-starter. It is a wedge, not a measured claim.

**How it stands apart: destination provenance vs prompt-content classifiers.** Classifiers ask "does this text look
like an attack?", and an attacker can reword it. We ask "did the user authorize this destination, and is it on the
allowlist?" Rewording doesn't change where the data goes. And unlike guardrails that are validated only on a
self-built simulator, every number here is measured against the organizer's real DVAA target with a live
default-deny egress boundary in the loop. We are *not* a better classifier:

| | What it is | Where Tourniquet fits |
|---|---|---|
| Falcon AIDR | CrowdStrike's enterprise AI detection and response platform | We complement it at the tool boundary. We have not integrated with it. Our alerts use an AIDR-shaped schema |
| NeMo Guardrails | NVIDIA's open-source toolkit of programmable rails inside the app | We need no app code changes: a sidecar in front of the chat endpoint plus an egress proxy |
| Lakera Guard, Prompt Guard | Classifiers that score text for injection or jailbreak | We decide on **where data goes**, not on how the text reads. Pair us with one of them |

Our edge, in five parts: **drop-in sidecar** · **default-deny egress at the tool boundary** · **deterministic rules**
(same input, same verdict) · **low false-positive posture** · **config, not runtime** — the proxy target, allowlist
and rules are deployment configuration loaded at startup, not runtime-mutable from the data path, so an attacker
reading and writing through the agent cannot change where traffic is allowed to go.

**Path to launch** (each step has a concrete exit test):
1. **Now, prototype:** the reverse proxy and egress guard run against DVAA and our own OpsBot, with a scored corpus and a working demo.
2. **Next, open-source sidecar:** one compose file in front of any OpenAI-compatible agent. Design partners run it in observe mode to measure false positives on their real traffic. *Exit test:* a partner leaves it in block mode.
3. **Then, paid managed policy and alert routing:** hosted allowlists and a honeytoken registry, with alerts routed to the tools a team already uses. This is the paid tier. *Proposed pricing model (a mechanism, not a quote — no dollar figure yet):* per protected agent, or per million tool calls — a usage unit that scales with what the buyer is protecting. The actual price will come from design partners, not a guess.
4. **Then, SOC integration:** alerts go into analyst triage. This already works offline as a prototype with our Track 1 SOC Brief (`scripts/soc-handoff.sh`).

**Evidence (from `results.json`).** Where data actually leaves, we prevent **57 of 71** exfil attempts with **0 of 164**
legitimate requests blocked. DVAA's own scanner prevents 64 of 71 but blocks 21 of 164.

**Market evidence (public, cited; not our numbers).** The failure we stop is a shipped-product reality — EchoLeak,
CVE-2025-32711, CVSS 9.3, exfiltrated Microsoft 365 Copilot data zero-click via a hidden email instruction
([TechRepublic](https://www.techrepublic.com/article/news-microsoft-365-copilot-flaw-echoleak/)). The deployer, not
the model vendor, is held liable (*Moffatt v. Air Canada*, BC tribunal, Feb 2024,
[ABA](https://www.americanbar.org/groups/business_law/resources/business-law-today/2024-february/bc-tribunal-confirms-companies-remain-liable-information-provided-ai-chatbot/)).
And the security market is already buying this capability: Prompt Security → SentinelOne (~$250M, Aug 2025,
[press](https://www.sentinelone.com/press/sentinelone-to-acquire-prompt-security/)) and Lakera → Check Point (Sep 2025).
Observe-then-block is the established SASE/SWG/DLP rollout pattern. Full brief with every citation:
[`demo/slides/MARKET-EVIDENCE.md`](MARKET-EVIDENCE.md).

---

## Speaker notes (about 30 seconds, about 80 words)

"Agents read untrusted text and act with your authority, so one hidden instruction can send customer data out.
Who pays: teams running agents they can't rebuild, without an enterprise AIDR budget.
Our wedge is an egress sidecar for agent tool calls. Classifiers judge the wording. We judge the destination, and rewording doesn't change it. Where data actually
leaves, we prevent 57 of 71 attempts with zero of 164 legitimate requests blocked. The baseline stops 64 but blocks 21.
Path: open-source sidecar with design partners, then paid managed policy, then SOC integration."

## Do not say
- Any market size, dollar price point, customer name, or "customers are asking". We have none of these. The pricing *mechanism* (per protected agent / per million tool calls) is fine to state as a proposed model, but never attach a number to it.
- "Better than Lakera / Prompt Guard / AIDR at detection." We didn't benchmark them.
- "57 of 71" on its own: always say the baseline's 64 of 71 at 21 of 164 blocked in the same breath.
- "Integrated with Falcon." It's an AIDR-*shaped* schema only.
