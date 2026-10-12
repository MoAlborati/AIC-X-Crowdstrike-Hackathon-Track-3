# Attribution & licenses for reused benchmark content

The T6 corpus **reuses** published attack cases from public benchmarks and from DVAA's own
organizer-provided payloads. No new attack content is authored. Each fixture also records its
`source` inline. Users of this corpus must honor the upstream licenses below.

## Sources

| Benchmark | Fixtures | License | Upstream |
|-----------|----------|---------|----------|
| **deepset/prompt-injections** | `fixtures/deepset/*` | Apache-2.0 | https://huggingface.co/datasets/deepset/prompt-injections |
| **AgentDojo** | `fixtures/agentdojo/*`, `fixtures/evasion/eva-bench-*` | MIT | https://github.com/ethz-spylab/agentdojo (Debenedetti et al., NeurIPS 2024 D&B) |
| **InjecAgent** | `fixtures/injecagent/*` | Apache-2.0 (code) | https://github.com/uiuc-kang-lab/InjecAgent (Zhan et al., ACL Findings 2024) |
| **DVAA** (organizer sandbox) | `fixtures/evasion/eva-pos-*`, baseline replica in `tools/baseline.mjs` | organizer-provided training sandbox | damn-vulnerable-ai-agent @ `57918267d8d529ceec6d40fc9836ab09d128eee4` |
| synthetic benign | `fixtures/benign/*`, `corpus/*` | this repo | authored benign-only material (no attack content) |

## Notes

- We reuse **short, canonical, representative** examples (attack templates / injection
  strings) from each benchmark for a defensive detector's evaluation corpus. For the full
  datasets, use the upstream sources above.
- Attack **destinations** are the benchmarks' own placeholders (`attacker@evil.example`,
  `attacker.example`) or DVAA's `127.0.0.1` canary. No real address is used.
- Secrets/credentials (`dvaa-admin-secret`, SSN `123-45-6789`) are FAKE DVAA sandbox values,
  identical to those in DVAA `SENSITIVE_DATA` and the T1 captures.
- The DVAA baseline replica in `tools/baseline.mjs` is copied verbatim (subset) from DVAA
  `src/core/vulnerabilities.js` at the pinned commit, for offline test parity.
