# CITATIONS — verified claims for the pitch

Checked 2026-10-12 against primary sources: vendor press releases, SEC filings, NVD/MSRC, the FBI IC3 PDFs, arXiv and publisher DOIs, PubMed, and Zenodo. Six parallel verification passes did the checking. Where no primary source could be fetched, the Notes column says so.

**Status:** VERIFIED means the claim matches the source as written. CORRECTED means the claim was wrong or imprecise, and the "Safe slide wording" column has the fixed version. UNVERIFIABLE means no primary source could be confirmed.

**Rule:** say only what is in the "Safe slide wording" column, on slides and on stage.

## CrowdStrike / Pangea / AIDR

| Claim | Status | Primary source | Safe slide wording | Notes |
|---|---|---|---|---|
| Pangea acquired Sep 16 2025 for ~$260M | CORRECTED | https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-pangea-to-secure-every-layer-of-enterprise-ai/ ; 10-Q: https://www.sec.gov/Archives/edgar/data/1535527/000153552725000033/crwd-20251031.htm | "CrowdStrike announced its Pangea acquisition on Sep 16 2025 (reported at ~$260M)." | The press release gives no price; $260M comes from press reports. The 10-Q (Note 11) says the deal closed Sep 26 2025, with ~$222.7M consideration plus ~$46.5M of vesting stock. |
| AIDR "up to 99% efficacy at sub-30ms latency" | VERIFIED | Pangea press release (above) | "Up to 99% efficacy at sub-30ms latency" (CrowdStrike, internal benchmark) | The release footnotes this as internal benchmark testing on GPU edge deployment. Keep "up to". |
| "180+ known prompt injection techniques" | CORRECTED (source) | https://www.crowdstrike.com/en-us/press-releases/crowdstrike-announces-general-availability-of-falcon-ai-detection-and-response/ | "Powered by … 180+ known prompt injection techniques" (Falcon AIDR GA, Dec 15 2025) | This is from the Dec 2025 GA release, not the Pangea release. |
| Charlotte AI AgentWorks launched Sep 16 2025 | VERIFIED (wording) | https://www.crowdstrike.com/en-us/press-releases/crowdstrike-unleashes-agentic-security-workforce-to-transform-security-operations/ | "Charlotte AI AgentWorks, a new, no-code platform that makes every security team an AI builder" (announced Fal.Con, Sep 16 2025) | Say "announced". The release gives no GA date. |
| Falcon AIDR GA Dec 2025, paired with NVIDIA NeMo Guardrails | CORRECTED | GA release (above); NeMo blog: https://www.crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/ | "Falcon AIDR GA Dec 15 2025; NVIDIA NeMo Guardrails integration added Mar 2026." | The NeMo blog is dated Mar 19 2026 and quotes "up to sub-100ms", not sub-30ms. |
| Kurtz: "each prompt becomes an entry point for the adversary" | VERIFIED | Pangea press release (above) | "AI is rewriting the enterprise attack surface at breakneck speed. Each prompt becomes an entry point for the adversary." — George Kurtz, CEO & founder | It starts a sentence, so the "E" is capitalized. |
| Sentonas: "Prompt injection is a frontier security problem… adversaries weaponize…" | CORRECTED | AIDR GA release (above) | "Prompt injection is a frontier security problem. Adversaries are injecting hidden instructions into GenAI tools to weaponize the very systems transforming how work gets done." — Michael Sentonas, president | Our earlier ellipsis dropped words in the middle of the quote. Use the full text. |
| "Prompts are the new malware" | VERIFIED | AIDR GA release (above) | "The AI interaction layer is the new attack surface and prompts are the new malware." | |

## Vulnerabilities and fraud figures

| Claim | Status | Primary source | Safe slide wording | Notes |
|---|---|---|---|---|
| EchoLeak CVE-2025-32711, CVSS 9.3 | CORRECTED (attribution) | https://nvd.nist.gov/vuln/detail/CVE-2025-32711 ; https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711 | "EchoLeak (CVE-2025-32711): zero-click prompt injection that leaks data from Microsoft 365 Copilot. Rated CVSS 9.3 Critical by Microsoft (June 2025)." | 9.3 is Microsoft's CVSS v3.1 score as the CNA. NVD's own score is **7.5 High**. The CVE text reads "AI command injection in M365 Copilot". "Zero-click" is Aim Labs' term, supported by UI:N. Patched server-side; no known in-the-wild exploitation. |
| FBI IC3 2024: BEC $2.77B, 21,442 complaints | VERIFIED | https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf | "$2.77B lost to BEC across 21,442 complaints (FBI IC3, 2024)." | Exact figure: $2,770,151,146. |
| FBI IC3 2025: BEC $3.046B, 24,768 complaints, >$30M AI-linked, 86% wire/ACH | VERIFIED (86% pending) | https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf | "BEC: $3.05B lost across 24,768 complaints in 2025; over $30M involved AI (FBI IC3 2025)." | Exact figure: $3,046,598,558. The 86% is an unlabeled pie slice, so check the chart by eye before quoting it. |
| "BEC, the $3 billion-a-year fraud" | CORRECTED (soften) | IC3 2024 and 2025 reports (above) | "BEC: a ~$3 billion-a-year fraud." | Yearly losses: 2022 $2.74B, 2023 $2.95B, 2024 $2.77B, 2025 $3.05B. Only 2025 exceeded $3B. |
| Arup deepfake $25.6M, 15 transfers | VERIFIED | https://edition.cnn.com/2024/05/16/tech/arup-deepfake-scam-loss-hong-kong-intl-hnk (Arup confirmation) | "Arup (2024): a deepfake video call of the CFO led a Hong Kong employee to wire HK$200M (~US$25.6M) in 15 transfers." | We did not fetch the Hong Kong Police briefing. |
| Rimasauskas fake-invoice BEC, $120M+ from Google/Facebook | VERIFIED (caveat) | https://www.justice.gov/usao-sdny/pr/lithuanian-man-sentenced-5-years-prison-theft-over-120-million-fraudulent-business | "Fake invoices took over $120M from two US tech giants; the scammer got 5 years (DOJ SDNY, 2019)." | DOJ does not name the victims; the press identifies them as Google and Facebook. The planning doc said "~$100M+", now fixed. |
| Lethal trifecta, Willison, Jun 16 2025 | VERIFIED | https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/ | "The 'lethal trifecta': private data, untrusted content, external communication (Simon Willison, Jun 2025)." | |

## Real-world incidents (opening hooks)

| Claim | Status | Primary source | Safe slide wording | Notes |
|---|---|---|---|---|
| Moffatt v. Air Canada: "Air Canada lost in court over its chatbot" | CORRECTED (wording) | https://www.canlii.org/en/bc/bccrt/doc/2024/2024bccrt149/2024bccrt149.html | "Air Canada lost a tribunal case over its chatbot (Moffatt v. Air Canada, 2024 BCCRT 149) and was ordered to pay ~C$812." | The BC Civil Resolution Tribunal decided it on Feb 14 2024, not a court: C$650.88 in damages, ~C$812 with interest and fees. The tribunal rejected Air Canada's "the chatbot is a separate entity" argument. CanLII blocked fetching, so this is from consistent secondary reports. |
| Chevy dealer $1 Tahoe ("legally binding, no takesies backsies") | CORRECTED (wording) | https://jalopnik.com/chevrolet-dealer-ai-help-chatbot-goes-rogue-pranksters-1851112556 | "A Chevy dealer's chatbot 'agreed' to sell a 2024 Tahoe for $1 — 'that's a legally binding offer – no takesies backsies.'" | Dec 2023, Chris Bakke. The bot was told to say it; **no car was sold**. STRATEGY's "sold a Tahoe" is now "agreed to sell". |
| Alexa dollhouse, San Diego, 2017 | CORRECTED | https://www.mediapost.com/publications/article/292547/amazon-alexa-hears-tv-report-orders-dollhouses-fo.html | "A San Diego TV anchor said 'Alexa ordered me a dollhouse' on air — and viewers' Echo devices tried to order dollhouses." | Anchor Jim Patton (CW6) did **not** say "Alexa, order me a dollhouse". We found no confirmed completed orders. The original Dallas order (6-year-old Brooke Neitzel) was real. |
| AP Twitter hack, Apr 23 2013, $136B | VERIFIED | https://www.bloomberg.com/news/2013-04-23/fake-report-erasing-136-billion-shows-market-s-fragility.html | "A hacked AP tweet claiming explosions at the White House briefly wiped ~$136 billion off the S&P 500." | The drop lasted about 3 minutes and then recovered. The Syrian Electronic Army claimed it. |
| Knight Capital | CORRECTED (loss figure) | https://www.sec.gov/litigation/admin/2013/34-70694.pdf | "Knight Capital lost ~$460 million in 45 minutes from a faulty deployment; the SEC fined it $12M under the Market Access Rule (Rule 15c3-5)." | The SEC order of Oct 16 2013 gives $460M. The often-quoted $440M was Knight's own early estimate. |
| "Wall Street learned in 2010 … broker's risk gate" | VERIFIED | https://www.sec.gov/rules/final/2010/34-63241-secg.htm | "Since 2010, SEC Rule 15c3-5 requires every order to pass a broker's pre-trade risk controls." | Adopted Nov 3 2010; compliance began in 2011. |
| Burger King "OK Google" ad, 2017 | VERIFIED | https://techcrunch.com/2017/04/12/google-home-has-stopped-answering-to-that-annoying-burger-king-ad/ | "Burger King's TV ad said 'OK Google, what is the Whopper burger?'; Google blocked it within hours." | Apr 12 2017. |
| DPD chatbot swearing | VERIFIED | https://au.news.yahoo.com/delivery-firm-ai-chatbot-swears-110839790.html | "DPD's chatbot swore at a customer and called DPD the 'worst delivery firm in the world' — DPD switched the AI off." | Jan 2024. |
| Hawaii false missile alert | VERIFIED | https://www.fcc.gov/node/215906 | "Hawaii sent a false 'ballistic missile inbound — this is not a drill' alert; it took 38 minutes to retract." | Jan 13 2018. |
| SQL injection first documented 1998 (Phrack 54) | VERIFIED | http://phrack.org/issues/54/8.html | "1998: SQL injection first publicly described (Rain Forest Puppy, Phrack #54)." | Dec 25 1998. The article does not use the term "SQL injection". |
| Agloe, NY paper town, "1930s" | CORRECTED | https://en.wikipedia.org/wiki/Agloe,_New_York | "Around 1930, mapmakers invented 'Agloe' as a copyright trap; a local business later took the name." | Sources disagree between the 1920s and 1930s. The "general store" is disputed. |

## Papers and benchmarks

| Claim | Status | Primary source | Safe slide wording | Notes |
|---|---|---|---|---|
| MELON, arXiv 2502.05174, ICML 2025 | CORRECTED (minor) | https://arxiv.org/abs/2502.05174 ; https://proceedings.mlr.press/v267/zhu25z.html | "MELON (Zhu et al., ICML 2025): re-run the agent with the user prompt masked; if the same tool calls appear, it was injected." | The last author is William Yang Wang; PMLR 267:80310–80329. On AgentDojo with GPT-4o, attack success rate (ASR) falls from 16.06% to 0.24%. |
| CaMeL "77% AgentDojo with provable security" | CORRECTED (needs baseline) | https://arxiv.org/abs/2503.18813 | "CaMeL solves 77% of AgentDojo tasks with provable security (vs. 84% undefended)." | Debenedetti et al. 2025. |
| AgentDojo: 97 tasks, 629 security cases | VERIFIED | https://arxiv.org/abs/2406.13352 | "AgentDojo: 97 realistic tasks, 629 security test cases (NeurIPS 2024)." | Counts are as stated in the paper; later package versions may differ. |
| InjecAgent: 1,054 cases, data-exfil subset | VERIFIED | https://arxiv.org/abs/2403.02691 | "InjecAgent: 1,054 test cases, 544 of them data-stealing (ACL Findings 2024)." | |
| Greshake et al. 2023, indirect prompt injection | VERIFIED | https://arxiv.org/abs/2302.12173 ; https://doi.org/10.1145/3605764.3623985 | "Greshake et al., 'Not What You've Signed Up For', AISec '23." | |
| Hardy 1988, Confused Deputy | VERIFIED | https://doi.org/10.1145/54289.871709 | "Hardy, 'The Confused Deputy', ACM SIGOPS OSR 22(4):36–38, 1988." | The subtitle "(or why capabilities might have been invented)" is the common citation form. |
| Gentner 1983, structure-mapping | VERIFIED | https://doi.org/10.1207/s15516709cog0702_3 | "Gentner, 'Structure-mapping: A theoretical framework for analogy', Cognitive Science 7(2):155–170, 1983." | |
| Holyoak & Thagard 1989 | CORRECTED (pages added) | https://doi.org/10.1207/s15516709cog1303_1 | "Holyoak & Thagard, Cognitive Science 13(3):295–355, 1989." | |
| Spotlighting (Hines et al. 2024) | VERIFIED | https://arxiv.org/abs/2403.14720 | "Spotlighting cut attack success from >50% to <2% (Hines et al., 2024)." | |
| Design Patterns (Beurer-Kellner et al. 2025) | VERIFIED | https://arxiv.org/abs/2506.08837 | "Beurer-Kellner et al., 'Design Patterns for Securing LLM Agents against Prompt Injections', 2025." | |
| Meta Agents Rule of Two | VERIFIED (date) | https://ai.meta.com/blog/practical-ai-agent-security/ | "Agents must satisfy no more than two of: untrustworthy inputs, sensitive systems/data, changing state or communicating externally (Meta, Oct 2025)." | Published Oct 31 2025. |
| Willison Dual LLM pattern | VERIFIED | https://simonwillison.net/2023/Apr/25/dual-llm-pattern/ | "Dual LLM pattern (Willison, Apr 2023)." | |

## Medication safety, frameworks, datasets

| Claim | Status | Primary source | Safe slide wording | Notes |
|---|---|---|---|---|
| CPOE alert override rates 49–96% | VERIFIED | https://pubmed.ncbi.nlm.nih.gov/16357358/ | "Drug safety alerts are overridden by clinicians in 49% to 96% of cases (van der Sijs, JAMIA 2006)." | A review of 17 studies. |
| ~90% of high-severity alerts overridden (Isaac 2009) | CORRECTED (PMID) | https://pubmed.ncbi.nlm.nih.gov/19204222/ | "Clinicians accepted only 10.4% of high-severity drug-interaction alerts (Isaac, Arch Intern Med 2009)." | The old PMID 19204211 was a different paper. |
| ~73% overridden (Nanji 2018) | VERIFIED | https://pubmed.ncbi.nlm.nih.gov/29092059/ | "73.3% of medication alerts were overridden (Nanji, JAMIA 2018)." | |
| Surgical checklist (Haynes 2009) | VERIFIED | https://pubmed.ncbi.nlm.nih.gov/19144931/ | "Deaths fell from 1.5% to 0.8%; complications from 11% to 7% (Haynes, NEJM 2009)." | "More than one-third" comes from the Harvard press release, not the paper. |
| Ontario checklist (Urbach 2014) | VERIFIED | https://pubmed.ncbi.nlm.nih.gov/24620866/ | "Mandated checklists in Ontario showed no significant reduction in mortality or complications (Urbach, NEJM 2014)." | |
| AIT-ADS 2.65M / 2.66M alerts | CORRECTED | https://zenodo.org/records/8263181 | "AIT-ADS: 2.66M labeled alerts (Wazuh 2.29M, Suricata 307k, AMiner 56k), 8 scenarios, CC-BY-4.0." | Exact count is 2,655,821. STRATEGY's "2.65M" is now fixed. |
| OWASP LLM Top 10 2025 IDs | VERIFIED | https://genai.owasp.org/llm-top-10/ | "LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM06 Excessive Agency · LLM07 System Prompt Leakage" | |
| OWASP Agentic Top 10 (Dec 2025) | VERIFIED (title) | https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/ | "OWASP Top 10 for Agentic Applications 2026: ASI01 Agent Goal Hijack · ASI02 Tool Misuse · ASI06 Memory & Context Poisoning · ASI09 Human-Agent Trust Exploitation" | Released Dec 9 2025, under the title "…2026". |
| Llama Prompt Guard 2 22M/86M, "mDeBERTa" | CORRECTED | https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M | "Prompt Guard 2: 86M (mDeBERTa-base) and 22M (DeBERTa-xsmall)." | Only the 86M model is mDeBERTa. |
| Confirmation of Payee 2 billion checks | VERIFIED (dated) | https://www.wearepay.uk/confirmation-of-payee-reaches-two-billion-checks-helping-protect-uk-consumers-against-fraud/ | "Confirmation of Payee passed 2 billion checks (Pay.UK, Mar 2024)." | |
| ATT&CK T1041 / T1567 | VERIFIED | https://attack.mitre.org/techniques/T1041/ ; https://attack.mitre.org/techniques/T1567/ | "T1041 Exfiltration Over C2 Channel · T1567 Exfiltration Over Web Service" | |

## Fixes made to the planning docs (this PR)

- **STRATEGY.md §2**
  - The Pangea price is now marked as press-reported, with the 10-Q figures added.
  - "180+ techniques" is moved to the Dec 15 2025 GA release.
  - The NeMo Guardrails pairing is redated to Mar 2026.
  - AgentWorks "launched" is now "announced".
  - The Kurtz quote is capitalized, and "prompts are the new malware" is added.
- **STRATEGY.md §7:** "lost in court" is now "lost a tribunal case", and "sold a Tahoe" is now "agreed to sell a Tahoe".
- **STRATEGY.md §8:** 2.65M is now 2.66M.
- **RESEARCH.md §B:** the Pangea line now gives the primary URL and notes that the price is press-reported. The GA release is added as the source for "180+" and "prompts are the new malware". The NeMo blog is dated Mar 2026, and the Kurtz and Sentonas quotes are now verbatim.
- **RESEARCH.md §C:** the OWASP Agentic title and date are now precise. EchoLeak's 9.3 is attributed to Microsoft, with NVD's 7.5 noted.
- **RESEARCH.md §D:** the Prompt Guard 2 architectures are fixed. CaMeL's 77% now has its 84% baseline.
- **RESEARCH.md §E:** AgentDojo and InjecAgent wording is fixed (544 data-stealing cases).
- **RESEARCH.md §F:** the Moffatt citation and award are added.
- **ADJACENT.md §7:** "the $3 billion-a-year fraud" is now "~$3 billion-a-year". Agloe's "1930s" is now "around 1930", and the store claim is softened.
- **ADJACENT.md §9:** the IC3 2025 figures are verified against the primary PDF, with the 86% still flagged. The Rimasauskas amount and victim naming are fixed. EchoLeak's CVSS is attributed. Holyoak & Thagard pages are added.
- **ADJACENT.md §10.4:** the Alexa pitch line quote and outcome are fixed.
- **ADJACENT.md §10.7**
  - The Isaac PMID is corrected (19204211 → 19204222). The medication citations are marked verified.
  - Moffatt now has its details, AP's $136B is verified via Bloomberg, and Knight Capital gets the SEC's $460M loss.
  - The MELON author name and PMLR pages are fixed.

## Still open

- **IC3 2025 "86% wire/ACH":** check the BEC pie chart in the PDF by eye before quoting it.
- **Moffatt award amount:** CanLII returned 403, so confirm the award on the CanLII page in a browser if you put the amount on a slide.
