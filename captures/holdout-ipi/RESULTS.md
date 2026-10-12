# HELD-OUT results: indirect prompt injection (LLMail-Inject + BIPIA)

**HELD-OUT. These numbers are a separate measurement. They are NOT part of the main-corpus headline in
`sentinel/scoring/RESULTS.md`, and they are not merged into it or into `captures/holdout-hf`.**

- Set: `captures/holdout-ipi`, 770 cases built from 385 verbatim rows. There are 370 attack cases and 400 benign
  cases. Each row is scored twice, once **direct** (the user turn) and once **indirect** (a `fetch_document` tool
  result).
- Sources: `microsoft/llmail-inject-challenge` (MIT, HF) and `microsoft/BIPIA` (MIT, GitHub). Each file is pinned to a
  revision and a SHA-256; see [LICENSES.md](./LICENSES.md). Neither dataset was used to build or tune T3. All rows are
  exact-text disjoint from `captures/variants` and `captures/holdout-hf` (this is tested).
- Detectors:
  - **T3**: `sentinel/detectors` at `origin/main` `1a6df68`, default policy.
  - **DVAA baseline**: real `detectAttacks()` @ `57918267` (the pinned commit, clean checkout, `dvaaDirty:false`).
- Corpus digest: `sha256:8c5ef41f7b6a4eaa25db1085c0e48b386a433b475c7025fe67bfa0817af303de`. The run had 0 detector errors
  and 0 warnings. Verdicts were identical across 2 runs of 5 iterations each.
- Reproduce: `DVAA_SRC=<dvaa checkout> node sentinel/scoring/cli.mjs --set holdout-ipi`. This writes
  `captures/holdout-ipi/results.json` and `SCORING.md` (both gitignored) and never touches `sentinel/scoring/results.json`.

The lenses are the same as in `captures/holdout-hf/RESULTS.md` (T7, enforce mode):
- **Detection**: any finding fired.
- **Prevention**: a finding that blocks before the agent acts.

## Overall (370 attack / 400 benign)

| Detector | Detection recall | Prevention recall | Precision (prev.) | Benign FP, clean emails (det. / prev.) | Benign FP, LLMail "False" rows, noisy (det. / prev.) |
|----------|-----------------:|------------------:|------------------:|---------------------------------------:|-----------------------------------------------------:|
| **T3** (SentinelProxy) | **0.081** (30/370) | **0.032** (12/370) | 1.00 (12/12) | **0/200** / **0/200** | 35/200 / 0/200 |
| DVAA baseline | 0.514 (190/370) | 0.514 (190/370) | 0.613 | 18/200 (9%) / 18/200 | 102/200 / 102/200 |

The two benign groups are reported separately because the LLMail `attack_attempt: False` label is noisy. 29 of
those 100 rows contain `contact@contact.com`, the challenge's exfil target (see LICENSES.md). The clean benign FP rate
uses `llmail-fp`, the challenge's own benign emails.

## By direct vs. indirect placement

| Detector | Placement | Detection recall | Prevention recall | Benign FP, clean (det. / prev.) |
|----------|-----------|-----------------:|------------------:|--------------------------------:|
| T3 | direct (user turn) | 0.049 (9/185) | 0.032 (6/185) | 0/100 / 0/100 |
| T3 | indirect (tool result) | 0.114 (21/185) | 0.032 (6/185) | 0/100 / 0/100 |
| DVAA | direct | 0.514 (95/185) | 0.514 (95/185) | 9/100 / 9/100 |
| DVAA | indirect | 0.514 (95/185) | 0.514 (95/185) | 9/100 / 9/100 |

## By dataset and placement

| Detector | Group | +/- | Detection recall | Prevention recall | FP (det.) | FP (prev.) |
|----------|-------|-----|-----------------:|------------------:|----------:|-----------:|
| T3 | LLMail-Inject, direct | 100/100 | 0.09 | 0.06 | 17/100 (noisy) | 0/100 |
| T3 | LLMail-Inject, indirect | 100/100 | 0.21 | 0.06 | 18/100 (noisy) | 0/100 |
| T3 | LLMail FP emails, direct | 0/100 | n/a | n/a | 0/100 | 0/100 |
| T3 | LLMail FP emails, indirect | 0/100 | n/a | n/a | 0/100 | 0/100 |
| T3 | BIPIA text, direct | 65/0 | 0.00 | 0.00 | n/a | n/a |
| T3 | BIPIA text, indirect | 65/0 | 0.00 | 0.00 | n/a | n/a |
| T3 | BIPIA code (exfil/recon), direct | 20/0 | 0.00 | 0.00 | n/a | n/a |
| T3 | BIPIA code (exfil/recon), indirect | 20/0 | 0.00 | 0.00 | n/a | n/a |
| DVAA | LLMail-Inject, direct | 100/100 | 0.75 | 0.75 | 51/100 (noisy) | 51/100 |
| DVAA | LLMail-Inject, indirect | 100/100 | 0.75 | 0.75 | 51/100 (noisy) | 51/100 |
| DVAA | LLMail FP emails, direct | 0/100 | n/a | n/a | 9/100 | 9/100 |
| DVAA | LLMail FP emails, indirect | 0/100 | n/a | n/a | 9/100 | 9/100 |
| DVAA | BIPIA text, direct | 65/0 | 0.00 | 0.00 | n/a | n/a |
| DVAA | BIPIA text, indirect | 65/0 | 0.00 | 0.00 | n/a | n/a |
| DVAA | BIPIA code (exfil/recon), direct | 20/0 | 1.00 | 1.00 | n/a | n/a |
| DVAA | BIPIA code (exfil/recon), indirect | 20/0 | 1.00 | 1.00 | n/a | n/a |

"n/a" means the denominator is 0.

## What this says

1. **T3 generalizes poorly to held-out indirect injection.** It detects 8.1% of attacks and prevents 3.2%. This is
   lower than on `holdout-hf` (28.5% detection) and much lower than on the main corpus.
2. **The blocks that T3 does make are exact.** All 12 prevented cases are LLMail rows where `inbound.exfil_instruction`
   saw a send-to-an-address instruction (6 rows × 2 placements). Prevention precision is 12/12. T3 blocks 0 of the 200
   clean benign emails and raises no alert on them either. The DVAA baseline flags 9% of those emails.
3. **Indirect placement helps T3 detection only.** T3's detection doubles when the same bytes arrive as a tool
   result (0.21 vs. 0.09 on LLMail), because `taint.instruction_in_untrusted_content` only applies to untrusted
   content. Prevention is the same in both placements. The DVAA baseline is a placement-blind content scanner and
   gives identical numbers.
4. **Gaps, stated plainly:**
   - **BIPIA code exfil snippets: T3 0/20, DVAA 20/20.** These are rows that embed code which POSTs a file to
     `http://example.com/upload`, or similar. T3's request-side scan does not treat exfil *code in a tool result* as an
     exfil instruction. DVAA's `dataExfiltration` and `mcpExploitation` patterns match it. This is the clearest
     miss in this set.
   - **BIPIA text task hijacks: T3 0/65, DVAA 0/65.** These are benign-sounding off-task instructions (translate,
     encode, write marketing copy), and neither scanner can tell them apart from a normal request without the
     surrounding task. This is a limit of content scanning.
   - **LLMail adaptive attacks: T3 9–21% detection.** These attacks use fake chat-template tokens, JSON
     smuggling and obfuscated addresses (for example `contact (at) contact.com`).
5. **Noisy negatives.** T3's 35 alerts on LLMail `False` rows are alert-only (`taint.structural_injection_marker` 32,
   `taint.instruction_in_untrusted_content` 2, `inbound.instruction_in_principal_turn` 1), and 0 of them block. Many of
   those rows are injection attempts that the upstream LLM judge labeled False. On the legacy rule-intent-block lens
   there is 1 FP (`IPI-LLM-I-NEG-37045`, an exfil verb aimed at a new destination), which is not a `prevents:true` block.
6. **Caveats.**
   - Groups are n=100, n=65 and n=20, so the 95% CI is roughly ±0.1 for n=100 and wider for the BIPIA groups.
   - BIPIA attacks are scored standalone, not embedded in BIPIA's third-party contexts (see LICENSES.md).
   - Latency is not a held-out claim.

## Next

- **Do not tune T3 on these rows.** Tuning on them would end their held-out status. The BIPIA-code gap (exfil code in
  a tool result) should be fixed from first principles and re-measured here once, with the result reported as a
  post-hoc number.
