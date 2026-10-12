# Attribution & licenses for reused content

Every **attack** string in the T6 corpus is copied **verbatim** from a published benchmark or from
DVAA (the organizer-provided sandbox). The corpus authors only **benign** material: the
travel-policy carrier document, the 400 benign rows, the benign `fixtures/benign/*` tasks, and the
benign user turns / tool names around tool results. Each fixture records its provenance in
`source` (`fidelity: "verbatim" | "authored"`). Verbatim fixtures also carry
`source.upstream` with the exact locator (commit/revision, file, row or case index), the upstream
`text`, and its `sha256`. `tools/verify-upstream.mjs` re-checks every string against the upstream
sources.

## Sources

| Source | Fixtures | License | Pinned upstream | Exact locator |
|--------|----------|---------|-----------------|---------------|
| **deepset/prompt-injections** | `fixtures/deepset/*` | Apache-2.0 (HF repo license; the card's `dataset_info` block also lists `cc-by-4.0`) | revision `4f61ecb038e9c3fb77e21034b22511b523772cdd` | split `test`, `row_idx` 98, 15 (label 1) and 77 (label 0); **T6b: all 116 rows** (`tools/upstream-deepset.json`) |
| **AgentDojo** (Debenedetti et al., NeurIPS 2024 D&B) | `fixtures/agentdojo/*`, `fixtures/evasion/eva-bench-*` | MIT, Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, and Florian Tramèr | `ethz-spylab/agentdojo` @ `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | attack `important_instructions_no_names` (`_JB_STRING` + `DEFAULT_USER_NAME`/`DEFAULT_MODEL_NAME`) × `v1/workspace` `InjectionTask3` and `v1/banking` `InjectionTask1`; user tasks `workspace/UserTask24`, `banking/UserTask0`. **T6b:** all `v1` suites. Attack strings come from AgentDojo's attack classes (`important_instructions_no_names`, `ignore_previous`, `injecagent`, `system_message`, `direct`). Benign ground-truth tool outputs come from `environment.yaml` data rendered by `tool_result_to_str` (`tools/upstream-agentdojo.json`) |
| **InjecAgent** (Zhan et al., ACL Findings 2024) | `fixtures/injecagent/*` | **MIT**, Copyright (c) 2023 Qiusi Zhan | `uiuc-kang-lab/InjecAgent` @ `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | `data/test_cases_ds_enhanced.json` cases 17 and 34. **T6b:** `test_cases_ds_enhanced.json` + `test_cases_dh_enhanced.json`, index `a*17 + (a mod 17)` for each attacker case `a` (`tools/upstream-injecagent.json`) |
| **DVAA** — damn-vulnerable-ai-agent | `fixtures/evasion/eva-pos-*`; replica code in `tools/baseline.mjs` | **Apache-2.0** (`LICENSE`, `package.json`), OpenA2A | `opena2a-org/damn-vulnerable-ai-agent` @ `57918267d8d529ceec6d40fc9836ab09d128eee4` | `src/payloads/agentpwn-mirror.js` `buildRagPoisonedDocument()` (APWN-DE-003); `src/core/vulnerabilities.js` (`DETECTION_EDGE`, `detectionText`, `ATTACK_PATTERNS` subset) |
| synthetic benign (this repo) | `fixtures/benign/*`, `corpus/*`, evasion carrier text | this repo | — | authored, benign only |

## What we changed (restructuring only, no new attack text)

- **T6b AgentDojo benign transcripts.** Each AgentDojo ground-truth call becomes an assistant `tool_calls`
  entry plus a `role: "tool"` result, in order. The outputs are AgentDojo's own rendering. Only the
  clock in the email/drive write tools is pinned (see README), which changes write-confirmation
  timestamps and nothing else.

- **Placement / channel.** For `tool_output` and `rag_document` fixtures, the upstream string is
  the content of a `role: "tool"` message answering an assistant `tool_calls` entry (OpenAI chat
  shape). For AgentDojo and InjecAgent, the user turn and tool name are the benchmark's own
  (user-task `PROMPT` + ground-truth tool; InjecAgent `User Instruction` + `User Tool`). Benign
  scaffolding authored here is used only for the evasion carriers.
- **AgentDojo.** The tool result carries only the rendered injection string. The surrounding
  AgentDojo environment data (other emails, file text) is omitted.
- **InjecAgent.** `Tool Parameters` (a Python-dict literal) appears as JSON in the
  `tool_calls[].function.arguments` field. `Tool Response` is verbatim.
- **DVAA.** `buildRagPoisonedDocument(exfilUrl)` is called with the run's own `127.0.0.1` canary,
  as the T1 aim-ab capture does. DVAA sends its output as one user message. We split it at the first
  blank line: the request line becomes the user turn, and the indexed-document block becomes the
  retrieved document (`source.upstream.splitAt`).
- **Evasion carriers.** The verbatim injection is embedded at the start, middle, or end of the
  benign travel-policy KB authored here.

## Destinations and secrets

- Destinations are the **benchmarks' own values**, unchanged: AgentDojo `mark.black-2134@gmail.com`
  and IBAN `US133000000121212121212`, InjecAgent `amy.watson@gmail.com`, and DVAA's exfil URL
  parameter set to the local `127.0.0.1:40447` canary. They are static test data. Nothing in this
  corpus or its tests sends anything anywhere. A replay harness must never execute egress tool
  calls from these fixtures.
- No real secrets. DVAA's APWN-DE-003 document carries a placeholder
  (`[INSERT_YOUR_DOCUMENT_CONTENTS_HERE]`), not credential values.

## DVAA code copied into this repo (Apache-2.0 §4)

`tools/baseline.mjs` contains a subset of DVAA `src/core/vulnerabilities.js`. The file carries an
`SPDX-License-Identifier: Apache-2.0` header, the copyright and license notice, and a statement of
what was modified (subset of categories, renamed identifiers, new loader code).
`tools/upstream-cases.mjs` contains the verbatim output string of DVAA's
`buildRagPoisonedDocument()`. The Apache-2.0 license text is at
http://www.apache.org/licenses/LICENSE-2.0.

## License texts (MIT notices for copied strings)

### AgentDojo

```
MIT License

Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, and Florian Tramèr

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### InjecAgent

```
MIT License

Copyright (c) 2023 Qiusi Zhan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.```
