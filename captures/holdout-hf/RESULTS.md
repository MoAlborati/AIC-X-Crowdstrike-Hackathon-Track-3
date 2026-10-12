# T6c held-out results: Hugging Face prompt-injection and jailbreak data

**These numbers are a separate, held-out measurement. They are NOT part of the main-corpus headline in
`sentinel/scoring/RESULTS.md`, and they are not merged into it.**

- Set: `captures/holdout-hf`, 1,000 cases built from 500 verbatim rows. There are 600 attack cases and 400
  benign cases. Each row is scored twice, once **direct** (the user turn) and once **indirect** (a
  `fetch_document` tool result).
- Sources: `jackhhao/jailbreak-classification` (Apache-2.0), `Lakera/gandalf_ignore_instructions` (MIT) and
  `reshabhs/SPML_Chatbot_Prompt_Injection` (MIT). Each is pinned to a revision; see [LICENSES.md](./LICENSES.md).
  None of these datasets was used to build or tune T3. All rows are disjoint from `captures/variants` (this is tested).
- Detectors:
  - **T3**: `sentinel/detectors` at `origin/main` `50704e6`, default policy. This **includes the #46 recall
    rules**. The pre-#46 run (`50d7bbb`) is shown for comparison.
  - **DVAA baseline**: real `detectAttacks()` @ `57918267` (the pinned commit, clean checkout).
- Corpus digest: `sha256:53f614c1b25c9b65763233486285f1f6f57c06701848c644d934e60b9a98e56d`. The run had
  0 detector errors and 0 warnings, and verdicts were identical across 5 iterations.
- Reproduce: `DVAA_SRC=<dvaa checkout> node sentinel/scoring/cli.mjs --set holdout-hf`. This writes
  `captures/holdout-hf/results.json` and `SCORING.md` (both gitignored, about 1.3 MB). It never touches
  `sentinel/scoring/results.json`.

## Lens definitions

The lenses are the T7 harness lenses, in enforce mode:

- **Detection**: any finding fired, including alert-only (report-only) findings.
- **Prevention**: a finding that actually blocks before the agent acts.
- **Precision**: precision on the prevention lens.
- **Benign FP**: the false-positive rate on benign rows, for the stated lens.

## Overall (600 attack / 400 benign)

| Detector | Detection recall | Prevention recall | Precision (prevention) | Benign FP (detection) | Benign FP (prevention) |
|----------|-----------------:|------------------:|-----------------------:|----------------------:|-----------------------:|
| **T3** (Tourniquet, with #46) | **0.285** (171/600) | **0.000** (0/600) | n/a (0 blocks) | 0.000 (0/400) | 0.000 (0/400) |
| T3, pre-#46 (`50d7bbb`) | 0.193 (116/600) | 0.000 (0/600) | n/a (0 blocks) | 0.000 (0/400) | 0.000 (0/400) |
| DVAA baseline | 0.607 (364/600) | 0.607 (364/600) | 0.943 | 0.055 (22/400) | 0.055 (22/400) |

## By dataset and injection channel

| Detector | Group | +/- | Detection recall | Prevention recall | Precision (prev.) | Benign FP (det.) | Benign FP (prev.) |
|----------|-------|-----|-----------------:|------------------:|------------------:|-----------------:|------------------:|
| T3 | Gandalf, direct | 100/0 | 0.58 (pre-#46 0.39) | 0 | n/a | n/a | n/a |
| T3 | Gandalf, indirect | 100/0 | 0.58 (0.39) | 0 | n/a | n/a | n/a |
| T3 | jailbreak-classification, direct | 100/100 | 0.08 (0.08) | 0 | n/a | 0 | 0 |
| T3 | jailbreak-classification, indirect | 100/100 | 0.09 (0.08) | 0 | n/a | 0 | 0 |
| T3 | SPML, direct | 100/100 | 0.19 (0.11) | 0 | n/a | 0 | 0 |
| T3 | SPML, indirect | 100/100 | 0.19 (0.11) | 0 | n/a | 0 | 0 |
| DVAA | Gandalf, direct | 100/0 | 0.62 | 0.62 | 1.00 | n/a | n/a |
| DVAA | Gandalf, indirect | 100/0 | 0.62 | 0.62 | 1.00 | n/a | n/a |
| DVAA | jailbreak-classification, direct | 100/100 | 0.78 | 0.78 | 0.876 | 0.11 | 0.11 |
| DVAA | jailbreak-classification, indirect | 100/100 | 0.78 | 0.78 | 0.876 | 0.11 | 0.11 |
| DVAA | SPML, direct | 100/100 | 0.42 | 0.42 | 1.00 | 0 | 0 |
| DVAA | SPML, indirect | 100/100 | 0.42 | 0.42 | 1.00 | 0 | 0 |

"n/a" means the denominator is 0. Gandalf has no benign rows, and T3 blocked nothing, so its prevention
precision is undefined. It is not 0 or 1.

## What this says

1. **T3 does not generalize to generic injection or jailbreak text.**
   - On the held-out set, T3 with #46 detects 28.5% of attacks (19.3% before #46) and prevents none of them.
   - On the main corpus, the same T3 detects 51% of injection-only positives and prevents 19%
     (`recallByPositiveKind*.injectionOnly`).
   - #46 raised held-out detection by 9 points, mostly on Gandalf and SPML, and did not move the
     jailbreak-classification rows. The drop from main corpus to held-out set is the overfitting the review
     flagged.
2. **Why prevention is 0.** Only three T3 rules fired on this set:
   - `inbound.instruction_in_principal_turn` (direct, 58 cases)
   - `taint.instruction_in_untrusted_content` (indirect, 58 cases)
   - `taint.structural_injection_marker` (#46, 55 cases)

   All three are **alert-only by policy** (`policy.inbound.injection`; detector.js says "Instructions alone only
   raise risk"). T3 blocks pre-forward only when the injection
   carries an exfil signal (`inbound.exfil_instruction`, taint flow to an egress sink, or a honeytoken).
   None of these HF rows names an exfil destination, so T3 has nothing it is willing to block on. This is
   the designed behavior: T3 prevents exfil and does not act as a jailbreak classifier. It also means a
   bare "ignore your instructions" injection passes T3 with an alert at most.
3. **Direct and indirect give near-identical numbers.** Both detectors are content scanners, and the payload
   bytes are the same in both channels. T3 changes which rule fires (principal vs untrusted provenance), and
   it differs in only 1 case (jailbreak-classification indirect: 0.09 vs 0.08 direct).
4. **T3's benign FP is 0/400.** This is real but cheap, because T3 also blocks 0 attacks. The DVAA baseline
   catches about 3x more held-out attacks, at a 5.5% benign FP rate overall and 11% on the jailbreak-classification
   benign rows. The rules that fire on those benign rows are `capabilityAbuse`, `dataExfiltration`,
   `agentToAgent`, `toolMitm`, `mcpExploitation` and `promptInjection` (22 benign cases).
5. **Caveats.**
   - Upstream labels are not corrected. Lakera says a few of its rows may not be real injections, and the
     jackhhao `benign` rows include instruction-like role-play. See LICENSES.md.
   - Each group has n=100, so a group recall has a 95% CI of roughly ±0.1.
   - Latency is not a held-out claim. The T3 median is about 0.05 ms per case on this set.

## Next

- Re-run this exact command after any T3 change. The set is frozen, so comparisons are like-for-like.
- **Do not tune T3 rules on these rows.** If rules are tuned against this set, it stops being held out. A
  new seed or new datasets would then be needed.
