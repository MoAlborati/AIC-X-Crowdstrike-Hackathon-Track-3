# Research & Evidence Base — Track 3

Compiled 2026-10-12 from 5 parallel research passes. Use these to cite on stage and to brief the build.

## A. Provided resources

- **DVAA — Damn Vulnerable AI Agent** (the Path-B target): https://github.com/opena2a-org/damn-vulnerable-ai-agent · Docker: https://hub.docker.com/r/opena2a/dvaa
  - 21 intentionally-vulnerable agents, Node.js ≥24, offline-capable, dashboard :9000, agents 7001–7023.
  - 12 OASB-1 categories; 22 CTF challenges; OpenAI-compatible `/v1/chat/completions`; `GET /api/attack-log`; per-reply `dvaa{}` ground-truth block; baseline `detectAttacks()` scans only head+tail 8KB; AIM capability-guard at tool boundary with A/B twins. (Full map in agent report; see STRATEGY §4.)
- **DVLLM** — AI security training platform, OWASP-LLM-Top-10 labs (offense + mitigation): https://dvllm.com/
- **AIT Alert Data Set (AIT-ADS)** — Track 1&2 dataset, 2.66M labeled synthetic SOC alerts (Wazuh 2.29M / Suricata 307k / AMiner 56k), 8 multi-step scenarios, `labels.csv`, CC-BY-4.0: https://zenodo.org/records/8263181 (DOI 10.5281/zenodo.8263181). *Creative use:* borrow its alert schema + correlation model to render our AI detections as a SOC feed; pre-index a tiny slice only.

## B. CrowdStrike product context (mirror this language)

- AgentWorks launch: https://www.crowdstrike.com/en-us/press-releases/crowdstrike-launches-charlotte-ai-agentworks-ecosystem-for-building-secure-agents/
- Pangea acquisition (announced Sep 16 2025; ~$260M is a *press-reported* figure, not stated by CrowdStrike; "up to 99% efficacy at sub-30ms latency", internal benchmark): https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-pangea-to-secure-every-layer-of-enterprise-ai/
- Falcon AIDR GA (Dec 15 2025; source of "180+ known prompt injection techniques" and "prompts are the new malware"): https://www.crowdstrike.com/en-us/press-releases/crowdstrike-announces-general-availability-of-falcon-ai-detection-and-response/ · blog: https://www.crowdstrike.com/en-us/blog/crowdstrike-secures-growing-ai-attack-surface-with-falcon-aidr
- AIDR + NVIDIA NeMo Guardrails (Mar 2026): https://www.crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
- Falcon detection field schema (for AIDR-shaped alert JSON): https://www.elastic.co/docs/reference/beats/filebeat/exported-fields-crowdstrike
- Product names to use verbatim: Charlotte AI · AgentWorks · Charlotte Agentic SOAR · Falcon AIDR · AgentWorks guardrails · Agentic Security Workforce.
- Quotes (verbatim; see CITATIONS.md): Kurtz (Pangea release) — "AI is rewriting the enterprise attack surface at breakneck speed. Each prompt becomes an entry point for the adversary." Sentonas (AIDR GA release) — "Prompt injection is a frontier security problem. Adversaries are injecting hidden instructions into GenAI tools to weaponize the very systems transforming how work gets done."
- **Judging criteria (OFFICIAL, from the organizers' slides, issue #128):** use the verbatim Track 3 brief and the Ciocca Venture Award text in `GOAL.md` / `STRATEGY.md` §0.
  - Track 3: fits the brief (build-and-defend vs prompt injection / tool misuse / data exfiltration, or attack a provided agent + build a detector) · one clear exploit or defense · demoed live · realistic scope, "rather than a fully hardened system" · maps to what CrowdStrike is building with AgentWorks. Prizes: 1st $800 · 2nd $200 · 3rd Prize Box.
  - Ciocca Venture Award (separate): clarity of the problem · who would use and pay · how it stands apart from existing tools · credible path from prototype to launch · alongside a working demo. Prizes: 1st $1000 · 2nd $500 · 3rd Prize Box.
- ~~Judging criteria (AgentWorks hackathon rules, closest proxy): problem-solving · agent design & scope · creativity & innovation · outcomes & workflow integration.~~ **SUPERSEDED 2026-10-12** by the official criteria above. Kept for history only; do not score against it. Rules: https://www.crowdstrike.com/en-us/legal/agentworks-hackathon/

## C. Threat frameworks (cite on the mapping slide)

- **OWASP Top 10 for LLM Apps (2025):** LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM06 Excessive Agency, LLM07 System Prompt Leakage. https://genai.owasp.org/llm-top-10/
- **OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10, released Dec 9 2025):** ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI06 Memory/Context Poisoning, ASI09 Human-Agent Trust. https://genai.owasp.org
- **MITRE ATLAS** (adversarial-ML tactics — most resonant with this SOC crowd): https://atlas.mitre.org
- **"Lethal trifecta"** (Simon Willison, Jun 2025): untrusted input + private data + external comms → exfil. https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- **EchoLeak (CVE-2025-32711, CVSS 9.3 Critical per Microsoft as CNA; NVD's own score is 7.5 High):** zero-click indirect prompt injection → exfil in M365 Copilot, via markdown-image/URL. The canonical real-world analog. https://www.cve.org/CVERecord?id=CVE-2025-32711

## D. Defensive techniques (build + credibility)

**Buildable detectors (ranked by impact/effort):**
1. **Tool-boundary taint + honeytoken + egress heuristics** — no model, ms latency, deterministic. Best ratio. (Our primary.)
2. **Meta Prompt Guard 2 (22M/86M)** — injection+jailbreak classifier (86M = mDeBERTa-base, 22M = DeBERTa-xsmall), CPU-capable, ~tens of ms, `pipeline()` one-liner. https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M
3. **ProtectAI deberta-v3-base-prompt-injection-v2** — Apache-2.0 injection classifier. https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
4. **Rebuff** (heuristics + LLM-judge + vector DB + **canary tokens**): https://github.com/protectai/rebuff · **Vigil** (YARA + classifier + canary): https://github.com/deadbits/vigil-llm · **Guardrails AI** (PII/output validators): https://github.com/guardrails-ai/guardrails · **NeMo Guardrails**: https://github.com/NVIDIA/NeMo-Guardrails

**Architectural defenses (cite, don't build):**
- **CaMeL — Defeating Prompt Injections by Design** (privileged planner + quarantined LLM + capability interpreter; 77% of AgentDojo tasks with provable security vs 84% undefended): https://arxiv.org/abs/2503.18813
- **Meta "Agents Rule of Two"** (≤2 of {untrusted input, sensitive data, external action} per session): https://ai.meta.com/blog/practical-ai-agent-security/
- **Dual-LLM pattern** (Willison, 2023): https://simonwillison.net/2023/Apr/25/dual-llm-pattern/

**Exfiltration detection signals (tool-call level):** markdown-image/URL exfil to non-allowlisted domains + URL length/entropy spikes; secrets/PII regex+entropy in egress args; **canary/honeytoken crossing an egress sink** (near-zero FP — best live gotcha); anomalous tool sequence (untrusted-read → sensitive-read → external-send in one turn); taint flag on untrusted-content tool outputs reaching a sink (highest-signal rule).

## E. Attack corpus / benchmarks (for real TPR/FPR numbers)

- **AgentDojo** (ETH SPY Lab, NeurIPS 2024 D&B): 97 realistic tasks, 629 security test cases; pip-installable; run one suite (e.g. Slack) locally in minutes. https://github.com/ethz-spylab/agentdojo · leaderboard https://agentdojo.spylab.ai · paper https://arxiv.org/abs/2406.13352
- **InjecAgent** (UIUC): 1,054 indirect-injection cases incl. 544 **data-stealing** cases (on-theme). https://github.com/uiuc-kang-lab/InjecAgent · paper https://arxiv.org/abs/2403.02691
- Also: Lakera **Gandalf** corpus; deepset `prompt-injections` HF dataset.
- **For the demo:** DVAA's own `dvaa{}` ground-truth labels give immediate precision/recall; AgentDojo/InjecAgent subsets add external-benchmark credibility (pre-compute, show a table).

## F. Relatable real-world incidents (opening hook)

- **Air Canada** chatbot refund — Moffatt v. Air Canada, 2024 BCCRT 149 — tribunal ordered the airline to pay ~C$812: https://guelph.ctvnews.ca/vancouver/article/air-canadas-chatbot-gave-a-bc-man-the-wrong-information-now-the-airline-has-to-pay-for-the-mistake · analysis: https://manatt.com/insights/newsletters/advertising-law/ai-gone-wild-airline-has-to-honor-a-refund-policy
- **Chevrolet of Watsonville** — "$1 Tahoe, legally binding": https://www.businessinsider.nl/a-car-dealership-added-an-ai-chatbot-to-its-site-then-all-hell-broke-loose
- **DPD** delivery chatbot made to swear: https://incidentdatabase.ai/reports/3605

## G. Creative differentiators (ranked; detail in STRATEGY §6–7)

COMMIT: Falcon-style AI incident graph (wow 5 / cost 2) · honeytoken tripwire (deterministic anchor) · AIDR-shaped alert JSON + MITRE ATLAS + OWASP mapping.
KEEP: split-screen attack/defense shell · taint-path source→sink glow · trust-score decay gauge (ties to DVAA AIM) · "drop-in guardrail" closing slide.
PRE-COMPUTE, don't run live: red-team variant generator (AgentDojo) · adaptive mutating attacker · AIT-dataset correlation.
AVOID live: anything nondeterministic in the 3-min window.
