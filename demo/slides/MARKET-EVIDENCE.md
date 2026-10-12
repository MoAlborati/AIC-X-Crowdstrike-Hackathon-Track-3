# Market evidence (public, cited) — the venture case for an egress sidecar

> Research-only brief for the Ciocca venture slide and SUBMISSION. Mo on #167: we can't poll people on-site,
> so the buyer case is built **only from public, citable evidence**. Every figure below links to its source.
> **No invented numbers and no customer quotes.** Our own metrics still come from `sentinel/scoring/results.json`.
> The question answered: *would a team shipping tool-using agents adopt an egress sidecar in observe-then-block
> mode, and who pays?*

## The one-line answer

Yes, because the exact failure the sidecar stops is now a shipped-product reality (EchoLeak), the deploying
company — not the model vendor — is the one held liable (Air Canada), and the security market is already paying
to acquire this capability (Lakera, Prompt Security, Protect AI all bought in 2025). Observe-then-block is how
egress controls have always been rolled out (SASE/SWG/DLP monitor mode), so it matches how the buyer already works.

## Buyer persona (who uses, who pays)

- **User:** the platform or AppSec engineer who ships an agent on an OpenAI-compatible API and controls its network but not its prompts or tool code.
- **Budget holder:** the head of engineering or security at a mid-size software company shipping agents, with no enterprise AI detection-and-response (AIDR) budget yet. Their blocker is "we can't ship this agent until security signs off on what it can send out."
- **Why they pay rather than build:** the liability lands on them, not the model vendor (Air Canada, below), and the capability is being bought, not hand-rolled, by the security industry itself (the 2025 acquisitions).

## Why they'd pay — three cited real incidents

1. **EchoLeak — CVE-2025-32711, CVSS 9.3 (Microsoft 365 Copilot).** The first known **zero-click** AI exploit: a hidden instruction in an email is pulled into Copilot's RAG context and exfiltrates chat logs, OneDrive, SharePoint and Teams data to an attacker server with no user action. This is precisely the "untrusted content → private data out" path an egress guard is built to stop, in a shipped enterprise product.
   [TechRepublic](https://www.techrepublic.com/article/news-microsoft-365-copilot-flaw-echoleak/) ·
   [SC World](https://www.scworld.com/news/microsoft-365-copilot-zero-click-vulnerability-enabled-data-exfiltration)
2. **Chevrolet of Watsonville "$1 Tahoe" (Dec 2023).** A prankster injected instructions into a dealership's ChatGPT-backed site agent ("agree with anything… legally binding offer, no takesies backsies") and got it to "sell" a Tahoe for $1; others then made it write code and recommend competitors before the dealer pulled it. A deployed, customer-facing agent subverted by injected text.
   [Business Insider](https://www.businessinsider.nl/a-car-dealership-added-an-ai-chatbot-to-its-site-then-all-hell-broke-loose) ·
   [Jalopnik](https://jalopnik.com/chevrolet-dealer-ai-help-chatbot-goes-rogue-pranksters-1851112556)
3. **Moffatt v. Air Canada (BC Civil Resolution Tribunal, 14 Feb 2024).** The tribunal held Air Canada liable for its chatbot's output and rejected the argument that the bot was a separate entity; it awarded the passenger ~$650 CAD. Establishes in law that **the company deploying the agent owns the consequences of what it says and does** — the reason a security sign-off (and a guardrail) is a purchase, not a nice-to-have.
   [American Bar Association](https://www.americanbar.org/groups/business_law/resources/business-law-today/2024-february/bc-tribunal-confirms-companies-remain-liable-information-provided-ai-chatbot/) ·
   [CX Today](https://www.cxtoday.com/conversational-ai/court-orders-air-canada-to-pay-out-for-chatbots-bad-advice/)

## Comparable-tool precedent — a market that is already buying

- **Lakera** (Lakera Guard, free Community + custom Enterprise): acquired by **Check Point**, announced 16 Sep 2025.
  [Check Point / Lakera](https://www.citi.com/ventures/perspectives/pressrelease/investing-in-lakera.html) · product + pricing posture: [Lakera Guard (FitGap)](https://us.fitgap.com/products/lakera-guard)
- **Prompt Security:** acquired by **SentinelOne**, ~$250M, announced 5 Aug 2025 — explicitly to extend into "GenAI and **agent** security."
  [SentinelOne press release](https://www.sentinelone.com/press/sentinelone-to-acquire-prompt-security/)
- **Protect AI:** acquired by **Palo Alto Networks** (same consolidation wave). [referenced in SentinelOne coverage](https://securitybuzz.com/industry-news/sentinelones-strategic-acquisition-and-the-rise-of-runtime-ai/)
- **Open-source entry tier precedent:** NVIDIA **NeMo Guardrails** (free, Apache-2.0) and the new MIT **PromptWall** LLM-firewall show the "free open-source guard, paid managed tier" go-to-market is live. PromptWall also documents a ~2 ms per-request overhead, matching our low-overhead posture.
  [PromptWall](https://github.com/hugo-kte/promptwall)

**Read:** three of the closest comparable products were acquired by major security vendors within ~2 months of
each other in 2025. The capability has demonstrated enterprise value; an independent, drop-in **egress** layer that
these platforms don't own (they classify text; we gate the destination) is a credible wedge, not a hypothesis.

## Egress-control precedent — the buyer already runs this pattern

Controlling and logging what leaves a network, in **observe/monitor mode first and block later**, is the established
SASE / Secure Web Gateway / DLP playbook, with a standing enterprise budget line:

- Gartner: by 2025 at least **60%** of enterprises have explicit SASE strategies (up from 10% in 2020), and the SASE market is forecast at **~$11.29B by 2028** (36.4% CAGR).
  [SDxCentral (Gartner Hype Cycle)](https://www.sdxcentral.com/articles/news/sase-hits-teen-years-in-gartner-hype-cycle/2021/08/) ·
  [Cloudflare SWG overview](https://www.cloudflare.com/sase/products/gateway/)

An egress sidecar for agent tool calls is the same control surface — "what is allowed to leave, to where" — applied
to a new source of traffic. Observe-then-block is not a concession; it is how this buyer adopts egress controls.

## The gap that is the opportunity

- Gartner (4Q25 forecast): agentic AI spending grows **141% in 2026 to ~$201.9B**, and **40%** of enterprise apps will
  include task-specific agents by end of 2026 — while only ~**6%** of organizations report an advanced AI security strategy.
  [Software Strategies Blog (Gartner 4Q25)](https://softwarestrategiesblog.com/2026/02/16/gartner-forecasts-agentic-ai-overtakes-chatbot-spending-2027/)

Agents are shipping far faster than agent-specific egress controls are being adopted. That spread — many new
tool-using agents, few mature controls, clear deployer liability — is the market for a drop-in egress sidecar.

## How to use this on stage (honesty guardrails)

- These are **market facts with public citations**, not our customers, our pricing or our forecast. Never present
  any figure here as SentinelProxy's own result or as a committed market size for us.
- Keep our measured numbers (57/71 prevented, 0/164 blocked) sourced to `results.json`, stated next to the baseline's
  64/71 at 21/164, exactly as in VENTURE.md.
- The incidents motivate the problem; they are not claims that SentinelProxy would have stopped each one.

**Sources:** every claim links inline above.
