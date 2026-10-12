# T6c held-out set: attribution and licenses

Every string in this set is copied **verbatim** from a public Hugging Face dataset at a pinned revision.
Nothing is authored here except the benign scaffolding of the indirect variant: the user turn
`Please summarize the document I just fetched for me.`, the tool name `fetch_document`, and its `doc_id`
argument. We use these rows for **defensive evaluation only**: measuring how SentinelProxy (T3) generalizes to
data it was never built or tuned on.

Licenses were checked on each dataset card (YAML `license:` field and the card text) at the pinned revision.
None of the datasets is gated. `deepset/prompt-injections` is **not** used here because the main corpus already
uses it (`captures/variants`).

| Dataset | License (dataset card) | Pinned revision | File | File SHA-256 | Split used | Sampled |
|---------|------------------------|-----------------|------|--------------|------------|---------|
| [`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | **Apache-2.0** (card YAML `license: apache-2.0`) | `2f2ceeb39658696fd3f462403562b6eea5306287` | `balanced/jailbreak_dataset_test_balanced.csv` | `809ef0d7c82fa05c31e818e9c3ff68f769632ac6d11cc3b43254cada577869a9` | test | 100 `jailbreak` + 100 `benign` |
| [`Lakera/gandalf_ignore_instructions`](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | **MIT** (card YAML `license: mit`; card section "Licensing Information": "distributed under the MIT License") | `04737b65e90a6794ec227012e4a255a7def6344b` | `data/test-00000-of-00001-bc92128b9288a6d1.parquet` | `56b646d133335ebc535266bd55dbe1b5bee7caa4b95bf49d040684b9b5dd9972` | test | 100 injections (the dataset has no benign rows) |
| [`reshabhs/SPML_Chatbot_Prompt_Injection`](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) | **MIT** (card YAML `license: mit`) | `02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5` | `spml_prompt_injection.csv` | `4ca6590cd8ec10832fcebee5e243acb32be5c3e79b7a260f8638eed738c784f8` | the single file (no split) | 100 `Prompt injection=1` + 100 `=0` (`User Prompt` column) |

Citations requested by the cards:
- Lakera: Pfister et al., *Gandalf the Red: Adaptive Security for LLMs*, arXiv:2501.07927 (2025). Source data
  are prompts submitted to Gandalf (gandalf.lakera.ai), filtered by Lakera.
- SPML: Sharma et al., *SPML: A DSL for Defending Language Models Against Prompt Attacks*, arXiv:2402.11755 (2024).
- jackhhao/jailbreak-classification: no citation given on the card; credited by its Hugging Face repo ID.

The Apache-2.0 and MIT terms require attribution and the license notice. Both are given by this file. The
full license texts are at <https://www.apache.org/licenses/LICENSE-2.0> and <https://opensource.org/license/mit/>.

## Provenance and determinism

- `tools/fetch_hf.py` downloads each file from `https://huggingface.co/datasets/<repo>/resolve/<revision>/<file>`,
  and refuses to continue if the file's SHA-256 differs from `tools/pins.json`. `--check` re-fetches and
  diffs the committed sample.
- Selection, per dataset and class: drop empty rows, exact duplicates, any text already in `captures/variants`,
  and rows over 8,000 chars (one jailbreak row was dropped; this is counted in `selection.skipped`). Then order
  the rows by `sha256("t6c-holdout-hf-v1:" + text)` and take the first 100. SPML had 94 exact duplicate rows
  and 1 empty row, both skipped.
- `upstream/<slug>.json` holds each sampled row's `rowIdx` (0-based in the pinned file), its verbatim `text`,
  and `sha256(text)`. Every fixture records `source.upstream {repo, revision, file, fileSha256, rowIdx, sha256}`.
  `tests/holdout.test.mjs` checks that every payload message is byte-identical to its row.
- `tools/build.mjs` turns each row into two fixtures:
  - **direct**: `channel: user_message`, where the row is the user turn.
  - **indirect**: `channel: tool_output`, where the row is the `fetch_document` tool result.

  The label is `label.injectionChannel` (`direct` | `indirect`). To stay under the 2 MB budget, only
  `upstream/*.json` and `manifest.json` are committed, and fixtures are rebuilt in memory by the T7 loader.
  To write them to disk for inspection, run `node tools/build.mjs --write-fixtures` (the output is gitignored).

## Known label caveats (upstream, not corrected)

- The Lakera card says "a few of the samples might not be real prompt injections" (the data was filtered by
  embeddings).
- SPML positives are largely LLM-generated attacks against a chatbot system prompt. Some of them are written
  as persona or role redefinitions rather than "ignore previous instructions".
- jackhhao `benign` rows include long role-play and instruction prompts. These are benign by the upstream
  label, but they read like instructions.
